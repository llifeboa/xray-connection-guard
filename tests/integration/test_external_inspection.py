#!/usr/bin/env python3
"""Exercise TUN, real DPI and IP bans through a supplied public VLESS node."""
import argparse
import contextlib
import http.client
import ipaddress
import json
import logging
import os
import queue
import socket
import struct
import tempfile
import time
import uuid
from pathlib import Path

import yaml

import guard
import inspector
import test_external_vless as external
import test_linux_tun as transport
import tun_network


TCP_PEERS = ["1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"]
LOCAL_RU_IP = "10.148.17.1"
BOOTSTRAPS = [("router.bittorrent.com", 6881), ("dht.transmissionbt.com", 6881),
              ("router.bt.ouinet.work", 6881)]


def control_https(port, expected=None, timeout=10):
    response = external.http_probe(port, "one.one.one.one", "/cdn-cgi/trace",
                                   address="1.1.1.1", timeout=timeout)
    assert response["status"] == 200, response
    values = dict(line.split("=", 1) for line in response["body"].splitlines() if "=" in line)
    address = str(ipaddress.ip_address(values["ip"]))
    if expected:
        assert address == expected, (address, expected)
    return address


def expect_blocked(port):
    try:
        control_https(port, timeout=2)
    except (OSError, EOFError, http.client.HTTPException):
        return
    raise AssertionError("HTTPS passed through a client/path that should be blocked")


def udp_send(stream, endpoint, address, port, payload):
    stream.sendto(bytes(3) + transport.encoded_address(address, port) + payload, endpoint)


def udp_dns(stream, endpoint):
    payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + \
              b"\x07example\x03com\x00\x00\x01\x00\x01"
    udp_send(stream, endpoint, "1.1.1.1", 53, payload)
    response = stream.recv(65535)
    prefix = bytes(3) + transport.encoded_address("1.1.1.1", 53)
    assert response.startswith(prefix), response.hex()
    message = response[len(prefix):]
    assert message[:2] == payload[:2] and message[2] & 128 and not message[3] & 15, message.hex()


def dht_peers():
    peers = {}
    for host, port in BOOTSTRAPS:
        for entry in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM):
            address = entry[4][0]
            if ipaddress.ip_address(address).is_global:
                peers.setdefault(address, port)
    assert len(peers) >= 6, peers
    return list(peers.items())[:6]


def exercise(args, root):
    outbound = external.parse_vless(args.uri_file)
    outbound["tag"] = "TO_FREEDOM"
    server = outbound["settings"]["vnext"][0]
    private_key, public_key = transport.key_pair(args.xray)
    peers = dht_peers()
    paths = inspector.Paths(root)
    paths.config.mkdir(parents=True)
    paths.state.write_text(json.dumps({"interface": transport.INTERFACE}))
    access = root / "ru-access.log"
    eve = root / "eve.json"
    access.touch()
    eve.touch()
    with tempfile.TemporaryDirectory(prefix="xray-external-secrets-") as private, \
            contextlib.ExitStack() as cleanup:
        credentials = Path(private)
        fragment = json.loads((Path(__file__).resolve().parents[2] /
                               "config/xray-tun.fragment.json").read_text())
        users = {name: str(uuid.uuid4()) for name in transport.CLIENT_IPS}
        transport.run(["ip", "link", "set", "lo", "up"])
        for address in [LOCAL_RU_IP, *transport.CLIENT_IPS.values()]:
            transport.run(["ip", "address", "add", address + "/32", "dev", "lo"])
        relay_config = {"log": {"access": str(access), "loglevel": "info"},
            "inbounds": [{"tag": "PUBLIC_RU_IN_2", "listen": LOCAL_RU_IP, "port": 1443,
                          "protocol": "vless", "settings": {"decryption": "none", "clients": [
                              {"id": user_id, "email": name + "@test"} for name, user_id in users.items()]},
                          "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                              "target": "1.1.1.1:443", "privateKey": private_key,
                              "serverNames": ["one.one.one.one"], "shortIds": ["abcd"]}}},
                         *fragment["inbounds"]],
            "outbounds": [*fragment["outbounds"], outbound], "routing": fragment["routing"]}
        relay_path = transport.save_config(credentials, "ru", relay_config)
        relay_path.chmod(0o600)
        transport.run([args.xray, "run", "-test", "-c", str(relay_path)])
        network = tun_network.Network(paths.network)
        cleanup.callback(network.clear)
        transport.launch(cleanup, [args.xray, "run", "-c", str(relay_path)], root, "ru-xray")
        transport.wait_for(transport.interface_ready, "native TUN")
        network.ensure(transport.INTERFACE)
        if args.trace:
            transport.trace_packets(cleanup, root)
        ports = {}
        for number, (name, address) in enumerate(transport.CLIENT_IPS.items()):
            port = 1080 + number
            client = transport.outbound("RU", LOCAL_RU_IP, 1443, users[name], public_key)
            client["streamSettings"]["realitySettings"]["serverName"] = "one.one.one.one"
            client["sendThrough"] = address
            client["mux"] = {"enabled": False, "xudpConcurrency": 8}
            path = transport.save_config(credentials, name, {"log": {"loglevel": "warning"},
                "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                              "settings": {"udp": True}}], "outbounds": [client]})
            transport.run([args.xray, "run", "-test", "-c", str(path)])
            transport.launch(cleanup, [args.xray, "run", "-c", str(path)], root, "client-" + name)
            transport.wait_for(lambda: transport.listening("127.0.0.1", port), "client SOCKS")
            ports[name] = port
        exit_before = control_https(ports["control"], args.expected_exit_ip)
        control_association, control_endpoint = transport.socks_request(ports["control"], 3, "0.0.0.0", 0)
        cleanup.callback(control_association.close)
        control_udp = cleanup.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        control_udp.settimeout(5)
        udp_dns(control_udp, control_endpoint)
        print(f"PASS: real external VLESS exit={exit_before}; TUN HTTPS and UDP DNS without DPI", flush=True)
        original = yaml.safe_load(args.suricata_config.read_text())
        paths.rules.write_text(inspector.RULE)
        paths.yaml.write_text(inspector.dump_config(inspector.configuration(original, paths, eve)))
        suricata_arguments = [args.binary, "-c", str(paths.yaml), "-q", str(inspector.QUEUE),
                              "--runmode", "workers"]
        cleanup.callback(inspector.update_queue, remove=True, paths=paths)
        inspector.update_queue(paths=paths)
        suricata = transport.launch(cleanup, suricata_arguments, root, "suricata")
        inspector.wait_ready()
        exit_inspected = control_https(ports["control"], args.expected_exit_ip)
        udp_dns(control_udp, control_endpoint)
        association, endpoint = transport.socks_request(ports["udp"], 3, "0.0.0.0", 0)
        cleanup.callback(association.close)
        udp = cleanup.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        udp.settimeout(5)
        cfg = {"access": {"type": "file", "path": str(access)}, "eve": {"type": "file", "path": str(eve)},
               "xray_timezone": "UTC", "audit_path": str(root / "audit.jsonl"),
               "correlation_buffer_seconds": 0.1, "inspection": {"interface": transport.INTERFACE},
               "firewall": {"host_network": True, "ban_seconds": 600, "allowlist_cidrs": []}}
        guard.validate(cfg)
        servers = guard.discover_server_ips()
        firewall = guard.Firewall(cfg["firewall"], servers)
        firewall.allowed_to_ban = lambda address: address in transport.CLIENT_IPS.values()
        firewall.ensure()
        correlator = guard.Correlator(cfg, servers, "enforce", firewall)
        events = queue.Queue()
        followers = [guard.FileFollower(str(access), "access", events),
                     guard.FileFollower(str(root / "ru-xray.log"), "access", events),
                     guard.FileFollower(str(eve), "eve", events)]
        for follower in followers:
            cleanup.callback(follower.close)

        def pump():
            for follower in followers:
                follower.step()
            while not events.empty():
                kind, line = events.get_nowait()
                correlator.add_eve(line) if kind == "eve" else correlator.add_access(line)
            correlator.process_pending()

        for path in (access, root / "ru-xray.log", eve):
            for line in path.read_text().splitlines():
                correlator.add_eve(line) if path == eve else correlator.add_access(line)
        for follower in followers:
            follower.step()
        handshake = b"\x13BitTorrent protocol" + bytes(8) + b"i" * 20 + b"-TEST00-" + b"p" * 12
        for peer in TCP_PEERS:
            with transport.socks_request(ports["tcp"], 1, peer, 443)[0] as stream:
                stream.sendall(handshake)
                time.sleep(0.2)
            pump()
        transport.wait_for(lambda: correlator.stats["bans"] == 1, "TCP client ban", step=pump)
        dht = b"d1:ad2:id20:abcdefghijklmnopqrst6:target20:abcdefghijklmnopqrste1:q9:find_node1:t2:aa1:y1:qe"
        for peer, port in peers:
            for attempt in range(5):
                udp_send(udp, endpoint, peer, port, dht)
                time.sleep(0.15)
                pump()
            print(f"DHT sent: {peer}:{port}, source={udp.getsockname()}", flush=True)
        transport.wait_for(lambda: correlator.stats["bans"] == 2, "UDP client ban", step=pump)
        records = [json.loads(line) for line in Path(cfg["audit_path"]).read_text().splitlines()]
        assert {record["client_ip"] for record in records} == {
            transport.CLIENT_IPS["tcp"], transport.CLIENT_IPS["udp"]}, records
        assert all(record["unique_peers"] >= 5 and record["unique_flows"] >= 5 and
                   record["ban_seconds"] == 600 and record["result"] == "banned-600s" for record in records)
        udp_record = next(record for record in records if record["client_ip"] == transport.CLIENT_IPS["udp"])
        udp_locals = {tuple(item["local"]) for item in udp_record["evidence"]}
        assert len(udp_locals) == 1, udp_locals
        alerts = [json.loads(line) for line in eve.read_text().splitlines()]
        blocked = [record for record in alerts if record.get("alert", {}).get("signature_id") == inspector.SID
                   and record["alert"].get("action") == "blocked"]
        assert {record["proto"] for record in blocked} >= {"TCP", "UDP"}, blocked
        expect_blocked(ports["tcp"])
        expect_blocked(ports["udp"])
        exit_after_bans = control_https(ports["control"], args.expected_exit_ip)
        udp_dns(control_udp, control_endpoint)
        state = json.loads(transport.run(["nft", "-j", "list", "set", "inet", guard.TABLE, "clients_v4"]).stdout)
        print("PASS: external exit with real nDPI TCP/DHT drops; two 600s IP bans; control HTTPS/DNS survives", flush=True)
        transport.stop(suricata)
        expect_blocked(ports["control"])
        transport.launch(cleanup, suricata_arguments, root, "suricata-restored")
        inspector.wait_ready()
        exit_restored = control_https(ports["control"], args.expected_exit_ip)
        print("PASS: missing Suricata fails closed; restart restores real external HTTPS", flush=True)
        endpoint_addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(
            server["address"], server["port"], socket.AF_INET, socket.SOCK_STREAM)})
        exit_table = "xray_guard_test_exit"
        transport.run(["nft", "add", "table", "inet", exit_table])
        try:
            rules = f"add chain inet {exit_table} output {{ type filter hook output priority -10; policy accept; }}\n"
            for address in endpoint_addresses:
                rules += (f"add rule inet {exit_table} output ip daddr {address} "
                          f"tcp dport {server['port']} drop\n")
            transport.run(["nft", "-f", "-"], input=rules)
            expect_blocked(ports["control"])
        finally:
            transport.run(["nft", "delete", "table", "inet", exit_table])
        exit_endpoint_restored = control_https(ports["control"], args.expected_exit_ip)
        print("PASS: external endpoint blocked fails closed; unblocking restores external HTTPS", flush=True)
        result = {"status": "passed", "external_endpoint": {"address": server["address"], "port": server["port"]},
            "transport": outbound["streamSettings"]["network"], "security": "reality",
            "flow": server["users"][0].get("flow", ""), "credentials_in_report": False,
            "exit_ip": {"before_dpi": exit_before, "with_dpi": exit_inspected,
                        "after_bans": exit_after_bans, "after_suricata_restart": exit_restored,
                        "after_endpoint_unblocked": exit_endpoint_restored},
            "udp_dns_before_and_after_dpi": True, "tcp_peer_ips": TCP_PEERS, "dht_peer_endpoints": peers,
            "dht_packets_per_peer": 5, "dht_single_local_endpoint": sorted(udp_locals),
            "bans": records, "nft_bans": state, "stats": dict(correlator.stats),
            "blocked_alerts": {protocol: sum(record["proto"] == protocol for record in blocked)
                               for protocol in ("TCP", "UDP")},
            "banned_clients_https_blocked": True, "control_client_survives": True,
            "missing_suricata_fails_closed": True,
            "external_endpoint_blocked_fails_closed": True,
            "guard_execution": "Production Correlator/Firewall in the test process; actual nftables",
            "reserved_clients_allowed_only_inside_test": True,
            "xray": transport.run([args.xray, "version"]).stdout}
        (root / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--xray", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--suricata-config", type=Path, required=True)
    parser.add_argument("--expected-exit-ip")
    parser.add_argument("--trace", action="store_true")
    args = parser.parse_args()
    if not os.environ.get("XRAY_GUARD_EXTERNAL_TEST") or not Path("/.dockerenv").is_file():
        parser.error("Only run inside a disposable Docker container on its own bridge network")
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    root = args.output.resolve()
    root.mkdir(mode=0o700)
    try:
        exercise(args, root)
    except BaseException:
        for path in root.glob("*.log"):
            print(f"\n{path.name}:\n" + "\n".join(path.read_text(errors="replace").splitlines()[-15:]), flush=True)
        raise


if __name__ == "__main__":
    main()
