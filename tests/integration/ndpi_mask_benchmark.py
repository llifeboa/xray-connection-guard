#!/usr/bin/env python3
"""Offline A/B measurements for build_ndpi_mask_comparison.py.

Synthetic addresses use benchmarking/documentation ranges. All runs use the
same Suricata executable/configuration and one CPU; only the loaded plugin
changes. CPU time includes startup, parsing, detection and EVE writing, but
excludes traffic generation and the compiler. It does not measure NFQUEUE.
"""
import collections
import hashlib
import ipaddress
import json
import os
import random
import signal
import socket
import ssl
import statistics
import struct
import subprocess
import time
from pathlib import Path

import inspector
import install_suricata


def checksum(data):
    data += bytes(len(data) % 2)
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def ip_packet(version, protocol, number, sport, dport, reverse, payload,
              sequence=0, acknowledgement=0, flags=24):
    # The destination and source addresses vary with the flow, preventing nDPI's
    # BitTorrent endpoint cache from contaminating unrelated synthetic cases.
    if version == 4:
        source = (int(ipaddress.IPv4Address('198.18.0.1')) + number).to_bytes(4, 'big')
        destination = (int(ipaddress.IPv4Address('198.19.0.1')) + number).to_bytes(4, 'big')
    else:
        source = (int(ipaddress.IPv6Address('2001:db8:1::1')) + number).to_bytes(16, 'big')
        destination = (int(ipaddress.IPv6Address('2001:db8:2::1')) + number).to_bytes(16, 'big')
    if reverse:
        source, destination, sport, dport = destination, source, dport, sport
    if protocol == 6:
        segment = struct.pack('!HHIIBBHHH', sport, dport, sequence, acknowledgement,
                              5 << 4, flags, 65535, 0, 0) + payload
        offset = 16
    else:
        segment = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
        offset = 6
    if version == 4:
        pseudo = source + destination + struct.pack('!BBH', 0, protocol, len(segment))
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(segment), 1, 0,
                             64, protocol, 0, source, destination)
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    else:
        pseudo = source + destination + struct.pack('!I3xB', len(segment), protocol)
        header = struct.pack('!IHBB16s16s', 6 << 28, len(segment), protocol, 64,
                             source, destination)
    value = checksum(pseudo + segment) or 65535
    segment = segment[:offset] + struct.pack('!H', value) + segment[offset + 2:]
    return header + segment


def tls_client_hello():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    connection = context.wrap_bio(incoming, outgoing, server_hostname='example.test')
    try:
        connection.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


CLIENT_HELLO = tls_client_hello()
BT_HANDSHAKE = b'\x13BitTorrent protocol' + bytes(8) + b'i' * 20 + b'-TEST00-' + b'p' * 12
DHT_QUERY = b'd1:ad2:id20:' + b'a' * 20 + b'e1:q4:ping1:t2:aa1:y1:qe'
DHT_REPLY = b'd1:rd2:id20:' + b'b' * 20 + b'e1:t2:aa1:y1:re'


def messages(kind, count):
    if kind == 'bittorrent_tcp':
        return [(False, BT_HANDSHAKE), (True, BT_HANDSHAKE)] + [
            (bool(i % 2), b'\0\0\0\x01\x02') for i in range(count)]
    if kind == 'dht':
        return [(bool(i % 2), DHT_REPLY if i % 2 else DHT_QUERY) for i in range(count)]
    if kind == 'utp':
        result = []
        for i in range(count):
            packet_type = 4 if i == 0 else 2 if i == 1 else 0
            header = struct.pack('!BBHIIIHH', (packet_type << 4) | 1, 0, 123,
                                 1000000 + i, 0, 65535, i + 1, i)
            result.append((bool(i % 2), header + (BT_HANDSHAKE if i > 1 else b'')))
        return result
    if kind == 'dns':
        question = b'\x07example\x04test\0\0\x01\0\x01'
        request = struct.pack('!HHHHHH', 1234, 256, 1, 0, 0, 0) + question
        reply = (struct.pack('!HHHHHH', 1234, 0x8180, 1, 1, 0, 0) + question +
                 b'\xc0\x0c\0\x01\0\x01\0\0\0\x3c\0\x04\xc6\x12\x00\x01')
        return [(bool(i % 2), reply if i % 2 else request) for i in range(count)]
    if kind == 'ntp':
        return [(bool(i % 2), bytes([0x24 if i % 2 else 0x23]) + bytes(47))
                for i in range(count)]
    if kind == 'unknown':
        rng = random.Random(17)
        return [(bool(i % 2), b'\xff\xfe\xfd\xfc' + rng.randbytes(92)) for i in range(count)]
    if kind in ('http', 'http_marker'):
        body = BT_HANDSHAKE if kind == 'http_marker' else b'x' * 1200
        request = b'GET /object HTTP/1.1\r\nHost: example.test\r\n\r\n'
        reply = (b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n'
                 b'Content-Length: ' + str(len(body) * count).encode() + b'\r\n\r\n')
        return [(False, request), (True, reply)] + [(True, body)] * count
    if kind == 'tls':
        # A syntactically valid TLS 1.2 ServerHello followed by opaque records.
        body = b'\x03\x03' + b's' * 32 + b'\0\xc0\x2f\0\0\0'
        hello = b'\x02' + len(body).to_bytes(3, 'big') + body
        server = b'\x16\x03\x03' + len(hello).to_bytes(2, 'big') + hello
        record = b'\x17\x03\x03' + (1200).to_bytes(2, 'big') + b'x' * 1200
        return [(False, CLIENT_HELLO), (True, server)] + [
            (bool(i % 2), record) for i in range(count)]
    raise ValueError(kind)


def flow_packets(kind, number, version=4, count=16):
    tcp = kind in ('bittorrent_tcp', 'http', 'http_marker', 'tls')
    dport = {'dns': 53, 'ntp': 123, 'http': 80, 'http_marker': 80, 'tls': 443}.get(kind, 43871)
    sport = 40000 + number % 20000
    seq = [100, 200]
    protocol = 6 if tcp else 17

    def emit(reverse, payload=b'', flags=24):
        direction = int(reverse)
        result = ip_packet(version, protocol, number, sport, dport, reverse, payload,
                           seq[direction], seq[1 - direction], flags)
        seq[direction] += len(payload) + bool(flags & 3)
        return result

    if tcp:
        yield ip_packet(version, 6, number, sport, dport, False, b'', 100, 0, 2)
        seq[0] += 1
        yield emit(True, flags=18)
        yield emit(False, flags=16)
    for reverse, payload in messages(kind, count):
        yield emit(reverse, payload)
        if tcp:
            yield emit(not reverse, flags=16)
    if tcp:
        yield emit(False, flags=17)
        yield emit(True, flags=17)
        yield emit(False, flags=16)


def write_capture(path, flows):
    packets = size = 0
    with path.open('wb') as output:
        output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
        for kind, number, version, count in flows:
            for packet in flow_packets(kind, number, version, count):
                elapsed = packets * 100
                output.write(struct.pack('<IIII', 1700000000 + elapsed // 1000000,
                                         elapsed % 1000000, len(packet), len(packet)))
                output.write(packet)
                packets += 1
                size += len(packet)
    digest = hashlib.sha256()
    with path.open('rb') as capture:
        while data := capture.read(1024 * 1024):
            digest.update(data)
    return {'packets': packets, 'ip_bytes': size, 'sha256': digest.hexdigest()}


def run_engine(work, binary, original, plugin, capture, label, flow_log=False):
    root = work / label
    root.mkdir()
    paths = inspector.Paths(root)
    paths.config.mkdir(parents=True)
    paths.rules.write_text(inspector.RULE)
    eve = root / 'eve.json'
    config = inspector.configuration(original, paths, eve)
    config['plugins'] = [plugin]
    if flow_log:
        config['outputs'][0]['eve-log']['types'].append('flow')
    paths.yaml.write_text(inspector.dump_config(config))
    args = [binary, '-c', str(paths.yaml), '-r', str(capture), '--runmode', 'single',
            '--simulate-ips', '-l', str(root)]
    with (root / 'engine.log').open('w') as log:
        process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
        start = time.monotonic()
        while True:
            pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid:
                process.returncode = os.waitstatus_to_exitcode(status)
                break
            if time.monotonic() - start > 240:
                process.send_signal(signal.SIGKILL)
                os.wait4(process.pid, 0)
                process.returncode = -signal.SIGKILL
                raise RuntimeError(f'Timed out: {label}; see {root / "engine.log"}')
            time.sleep(0.02)
    if process.returncode:
        raise RuntimeError(f'Suricata exited {process.returncode}: {root / "engine.log"}')
    rows = [json.loads(line) for line in eve.read_text().splitlines()] if eve.exists() else []
    alerts = [row for row in rows if row.get('alert', {}).get('signature_id') == inspector.SID]
    result = {'cpu_seconds': usage.ru_utime + usage.ru_stime,
              'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime,
              'wall_seconds': time.monotonic() - start,
              'alert_count': len(alerts), 'alert_flows': len({row['flow_id'] for row in alerts})}
    return result, rows


def startup_overhead(work, binary, original, plugins):
    root = work / 'startup-overhead'
    root.mkdir()
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    capture = root / 'one-packet.pcap'
    write_capture(capture, [('unknown', 0, 4, 1)])
    report = {'note': 'One UDP packet estimates initialization and shutdown cost.',
              'samples': {mode: [] for mode in plugins}}
    for mode, plugin in plugins.items():
        run_engine(root, binary, original, plugin, capture, f'warmup-{mode}')
    for repetition in range(4):
        modes = list(plugins) if repetition % 2 == 0 else list(reversed(plugins))
        for mode in modes:
            metrics, _ = run_engine(root, binary, original, plugins[mode], capture,
                                    f'{repetition}-{mode}')
            report['samples'][mode].append(metrics)
    report['median_cpu_seconds'] = {mode: statistics.median(
        row['cpu_seconds'] for row in samples) for mode, samples in report['samples'].items()}
    print(json.dumps({'startup_overhead': report}), flush=True)
    return report


def false_positive_evidence(workload, rows):
    """Describe synthetic ordinary-traffic alerts without saving endpoints."""
    evidence, seen = [], set()
    for row in rows:
        if row.get('alert', {}).get('signature_id') != inspector.SID or row['flow_id'] in seen:
            continue
        seen.add(row['flow_id'])
        source = ipaddress.ip_address(row['src_ip'])
        client_network = ipaddress.ip_network(
            '198.18.0.0/16' if source.version == 4 else '2001:db8:1::/64')
        source_is_client = source in client_network
        evidence.append({
            'workload': workload, 'app_proto': row.get('app_proto'), 'transport': row['proto'],
            'client_source_port': row['src_port' if source_is_client else 'dest_port'],
            'service_port': row['dest_port' if source_is_client else 'src_port'],
            'ndpi_confidence': row.get('ndpi', {}).get('confidence')})
    return evidence


def compare(work, binary, original, plugins):
    available = sorted(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {available[0]})
    results = {'note': 'Local offline single-CPU replay; not an inline server benchmark.',
               'versions': {'suricata': install_suricata.SURICATA_VERSION,
                            'ndpi': install_suricata.NDPI_VERSION},
               'sources': {name: {'url': url, 'sha256': digest}
                           for name, (url, digest) in install_suricata.SOURCES.items()},
               'method': {'runmode': 'single', 'simulate_ips': True,
                          'timing': 'wait4 child user + system CPU time, including startup/shutdown',
                          'samples_per_workload_and_mode': 4, 'order': 'ABBAABBA',
                          'rule': inspector.RULE.strip(), 'measures_nfqueue': False,
                          'memory_measurement': False},
               'cpu_affinity': [available[0]], 'correctness': {}, 'benchmarks': {}, 'upstream': {},
               'performance_false_positive_evidence': []}
    results['startup_overhead'] = startup_overhead(work, binary, original, plugins)
    cases = [(kind, version) for kind in ('bittorrent_tcp', 'dht', 'utp', 'http', 'tls', 'dns',
                                        'ntp', 'unknown', 'http_marker') for version in (4, 6)]
    capture = work / 'correctness.pcap'
    results['synthetic_capture'] = write_capture(capture, [
        (kind, number, version, 20) for number, (kind, version) in enumerate(cases)])
    for mode, plugin in plugins.items():
        print(f'[comparison] Correctness: {mode}', flush=True)
        metrics, rows = run_engine(work, binary, original, plugin, capture,
                                   f'correctness-{mode}', flow_log=True)
        matches = collections.Counter()
        protocols = collections.defaultdict(set)
        for row in rows:
            address = ipaddress.ip_address(row['src_ip'])
            bases = ('198.18.0.1', '198.19.0.1') if address.version == 4 else (
                '2001:db8:1::1', '2001:db8:2::1')
            number = next((int(address) - int(ipaddress.ip_address(base)) for base in bases
                           if 0 <= int(address) - int(ipaddress.ip_address(base)) < len(cases)), None)
            if number is None:
                continue
            label = f'{cases[number][0]}_ipv{cases[number][1]}'
            protocols[label].add(row.get('ndpi', {}).get('proto', 'Unknown'))
            if row.get('alert', {}).get('signature_id') == inspector.SID:
                matches[label] += 1
        results['correctness'][mode] = {'metrics': metrics, 'cases': {
            f'{kind}_ipv{version}': {'expected_bittorrent': kind in ('bittorrent_tcp', 'dht', 'utp'),
                                    'alerts': matches[f'{kind}_ipv{version}'],
                                    'protocols': sorted(protocols[f'{kind}_ipv{version}'])}
            for kind, version in cases}}
    baseline = results['correctness']['all']['cases']
    candidate = results['correctness']['bittorrent']['cases']
    results['correctness_summary'] = {
        'added_bittorrent_cases': [name for name in baseline
                                   if candidate[name]['alerts'] and not baseline[name]['alerts']],
        'lost_bittorrent_cases': [name for name in baseline
                                  if baseline[name]['alerts'] and not candidate[name]['alerts']],
        'missed_expected_bittorrent': {mode: [name for name, row in outcome['cases'].items()
                                             if row['expected_bittorrent'] and not row['alerts']]
                                        for mode, outcome in results['correctness'].items()},
        'benign_alert_cases': {mode: [name for name, row in outcome['cases'].items()
                                      if not row['expected_bittorrent'] and row['alerts']]
                               for mode, outcome in results['correctness'].items()}}
    print(json.dumps({'correctness_summary': results['correctness_summary']}), flush=True)
    (work / 'results.json').write_text(json.dumps(results, indent=2))
    workloads = {
        'new_web_flows': [('http' if i % 2 else 'tls', i, 4 if i % 3 else 6, 8)
                          for i in range(16000)],
        'udp_flows': [(('dns', 'ntp', 'unknown')[i % 3], i, 4 if i % 2 else 6, 10)
                      for i in range(20000)],
        'long_web_flows': [('http' if i % 2 else 'tls', i, 4 if i % 3 else 6, 256)
                           for i in range(1000)]}
    for name, flows in workloads.items():
        print(f'[comparison] Generating workload: {name}', flush=True)
        capture = work / f'{name}.pcap'
        report = {'flows': len(flows), 'capture': write_capture(capture, flows),
                  'samples': {'all': [], 'bittorrent': []}}
        for mode, plugin in plugins.items():
            run_engine(work, binary, original, plugin, capture, f'{name}-warmup-{mode}')
        # Alternate order to reduce cache, temperature and scheduling bias.
        for repetition in range(4):
            modes = list(plugins) if repetition % 2 == 0 else list(reversed(plugins))
            for mode in modes:
                print(f'[comparison] {name}: {mode}, run {repetition + 1}/4', flush=True)
                metrics, rows = run_engine(work, binary, original, plugins[mode], capture,
                                           f'{name}-{repetition}-{mode}')
                report['samples'][mode].append(metrics)
                if repetition == 0 and mode == 'bittorrent':
                    results['performance_false_positive_evidence'].extend(
                        false_positive_evidence(name, rows))
        report['median_cpu_seconds'] = {mode: statistics.median(
            row['cpu_seconds'] for row in samples) for mode, samples in report['samples'].items()}
        report['bittorrent_cpu_change_percent'] = 100 * (
            report['median_cpu_seconds']['bittorrent'] / report['median_cpu_seconds']['all'] - 1)
        results['benchmarks'][name] = report
        print(json.dumps({'workload': name, 'median_cpu_seconds': report['median_cpu_seconds'],
                          'change_percent': report['bittorrent_cpu_change_percent']}), flush=True)
        (work / 'results.json').write_text(json.dumps(results, indent=2))
    for capture in sorted((work / 'upstream-pcaps').glob('*')):
        print(f'[comparison] Upstream capture: {capture.name}', flush=True)
        results['upstream'][capture.name] = {}
        for mode, plugin in plugins.items():
            metrics, _ = run_engine(work, binary, original, plugin, capture,
                                    f'upstream-{capture.name}-{mode}')
            results['upstream'][capture.name][mode] = metrics
        (work / 'results.json').write_text(json.dumps(results, indent=2))
    print(f'[comparison] Results: {work / "results.json"}', flush=True)


if __name__ == '__main__':
    import argparse
    import yaml
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('lab', type=Path)
    args = parser.parse_args()
    manifest = json.loads((args.lab / 'manifest.json').read_text())
    compare(args.lab, manifest['binary'], yaml.safe_load(Path(manifest['base']).read_text()),
            manifest['plugins'])
