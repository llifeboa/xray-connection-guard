#!/usr/bin/env python3
"""Exercise native Xray TUN and interface NFQUEUE inside private network namespaces."""
import argparse
import contextlib
import ipaddress
import json
import logging
import os
import queue
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

import yaml

import guard
import inspector
import tun_network


INTERFACE = "xray-guard"
RU_IP = "192.0.2.1"
EXIT_IP = "192.0.2.2"
TUN_IP = "198.18.0.1"
CLIENT_IPS = {"tcp": "203.0.113.20", "udp": "203.0.113.21", "control": "203.0.113.30"}
PEERS = [f"198.51.100.{number}" for number in range(10, 15)]
CONTROL_PEER = "198.51.100.20"
SECOND_CONTROL_PEER = "198.51.100.21"
PEER_PORT = 6881


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=30, **kwargs)


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def launch(cleanup, arguments, root, name, **kwargs):
    output = cleanup.enter_context((root / f"{name}.log").open("w"))
    process = subprocess.Popen(arguments, stdout=output, stderr=subprocess.STDOUT,
                               start_new_session=True, env=dict(os.environ, TZ="UTC"), **kwargs)
    cleanup.callback(stop, process)
    return process


def wait_for(predicate, label, timeout=15, step=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if step:
            step()
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(f"Timed out: {label}")


def listening(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.2):
            return True
    except OSError:
        return False


def interface_ready():
    result = subprocess.run(["ip", "-j", "link", "show", "dev", INTERFACE],
                            capture_output=True, text=True, check=False)
    return result.returncode == 0 and "UP" in json.loads(result.stdout)[0]["flags"]


def save_config(root, name, config):
    path = root / f"{name}.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def key_pair(binary):
    values = dict(line.split(": ", 1) for line in run([binary, "x25519"]).stdout.splitlines()
                  if ": " in line)
    public_key = values.get("PublicKey") or values.get("Password") or values.get("Password (PublicKey)")
    if not public_key:
        raise RuntimeError("Xray x25519 did not return a public key")
    return values["PrivateKey"], public_key


def reality(private_key=None, public_key=None, network="raw"):
    settings = {"network": network, "security": "reality"}
    if private_key:
        settings["realitySettings"] = {"target": f"{EXIT_IP}:9443", "privateKey": private_key,
                                       "serverNames": ["guard.test"], "shortIds": ["abcd"]}
    else:
        settings["realitySettings"] = {"serverName": "guard.test", "publicKey": public_key,
                                       "fingerprint": "firefox", "shortId": "abcd"}
    if network == "xhttp":
        settings["xhttpSettings"] = {"path": "/guard-test", "mode": "auto"}
    return settings


def outbound(tag, address, port, user_id, public_key, network="raw"):
    return {"tag": tag, "protocol": "vless", "settings": {"vnext": [{
        "address": address, "port": port, "users": [{"id": user_id, "encryption": "none"}]}]},
        "streamSettings": reality(public_key=public_key, network=network)}


def received(root, protocol, source, destination, payload):
    record = {"protocol": protocol, "source": source, "destination": destination, "payload": payload.hex()}
    with (root / "received.jsonl").open("a") as output:
        output.write(json.dumps(record) + "\n")


def echo_tcp(listener, root):
    def handle(stream):
        with stream:
            stream.settimeout(60)
            try:
                while payload := stream.recv(65535):
                    received(root, "TCP", stream.getpeername()[0], stream.getsockname()[0], payload)
                    stream.sendall(payload)
            except OSError:
                pass
    try:
        while True:
            stream, _ = listener.accept()
            threading.Thread(target=handle, args=(stream,), daemon=True).start()
    except OSError:
        return


def echo_udp(listener, root):
    try:
        while True:
            payload, address = listener.recvfrom(65535)
            received(root, "UDP", address[0], listener.getsockname()[0], payload)
            listener.sendto(payload, address)
    except OSError:
        return


def tls_server(listener, context):
    def handle(stream):
        with stream:
            stream.settimeout(5)
            try:
                with context.wrap_socket(stream, server_side=True) as secured:
                    while secured.recv(65535):
                        pass
            except (OSError, ssl.SSLError):
                pass
    try:
        while True:
            stream, _ = listener.accept()
            threading.Thread(target=handle, args=(stream,), daemon=True).start()
    except OSError:
        return


def exit_worker(args):
    def terminate(signum, frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, terminate)
    root = args.exit_worker
    if sys.stdin.readline().strip() != "start":
        raise SystemExit("Missing namespace setup")
    run(["ip", "link", "set", "lo", "up"])
    with contextlib.ExitStack() as cleanup:
        for address in PEERS + [CONTROL_PEER, SECOND_CONTROL_PEER]:
            version = ipaddress.ip_address(address).version
            run(["ip", f"-{version}", "address", "add", f"{address}/{32 if version == 4 else 128}",
                 "dev", "lo"] + (["nodad"] if version == 6 else []))
            for kind, handler in ((socket.SOCK_STREAM, echo_tcp), (socket.SOCK_DGRAM, echo_udp)):
                listener = cleanup.enter_context(socket.socket(
                    socket.AF_INET if version == 4 else socket.AF_INET6, kind))
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((address, PEER_PORT))
                if kind == socket.SOCK_STREAM:
                    listener.listen(32)
                threading.Thread(target=handler, args=(listener, root), daemon=True).start()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["h2", "http/1.1"])
        context.load_cert_chain(str(root / "cert.pem"), str(root / "key.pem"))
        listener = cleanup.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        listener.bind((EXIT_IP, 9443))
        listener.listen(32)
        threading.Thread(target=tls_server, args=(listener, context), daemon=True).start()
        launch(cleanup, [args.xray, "run", "-c", str(root / "exit.json")], root, "exit-xray")
        wait_for(lambda: listening(EXIT_IP, 2443) and listening(EXIT_IP, 9443), "exit listeners")
        (root / "exit.ready").touch()
        sys.stdin.read()


def receive(stream, length):
    payload = bytearray()
    while len(payload) < length:
        part = stream.recv(length - len(payload))
        if not part:
            raise EOFError("SOCKS connection closed")
        payload.extend(part)
    return bytes(payload)


def encoded_address(address, port):
    try:
        parsed = ipaddress.ip_address(address)
        encoded = bytes([1 if parsed.version == 4 else 4]) + parsed.packed
    except ValueError:
        domain = address.encode("idna")
        encoded = bytes([3, len(domain)]) + domain
    return encoded + struct.pack("!H", port)


def socks_request(port, command, address, destination_port):
    stream = socket.create_connection(("127.0.0.1", port), timeout=10)
    stream.sendall(b"\x05\x01\x00")
    assert receive(stream, 2) == b"\x05\x00"
    stream.sendall(b"\x05" + bytes([command]) + b"\x00" + encoded_address(address, destination_port))
    version, status, reserved, family = receive(stream, 4)
    assert version == 5 and status == 0 and reserved == 0, (version, status, reserved)
    length = {1: 4, 4: 16}[family]
    endpoint = (str(ipaddress.ip_address(receive(stream, length))), struct.unpack("!H", receive(stream, 2))[0])
    return stream, endpoint


def tcp_connect(port, address):
    return socks_request(port, 1, address, PEER_PORT)[0]


def udp_send(stream, endpoint, address, payload):
    stream.sendto(b"\x00\x00\x00" + encoded_address(address, PEER_PORT) + payload, endpoint)


def check_udp_echo(stream, endpoint, address):
    payload = b"guard-ordinary-udp"
    udp_send(stream, endpoint, address, payload)
    reply = stream.recv(65535)
    assert reply == b"\x00\x00\x00" + encoded_address(address, PEER_PORT) + payload, reply


def check_tcp_echo(port, payload, address=CONTROL_PEER):
    with tcp_connect(port, address) as stream:
        stream.sendall(payload)
        assert receive(stream, len(payload)) == payload


def check_tcp_blocked(port):
    try:
        with tcp_connect(port, CONTROL_PEER) as stream:
            stream.settimeout(0.5)
            stream.sendall(b"must-not-bypass")
            assert not stream.recv(65535), "Traffic bypassed the required TUN/NFQUEUE path"
    except (OSError, EOFError):
        pass


def check_tun_failure(port, worker):
    run(["ip", "link", "set", INTERFACE, "down"])
    try:
        check_tcp_blocked(port)
    finally:
        run(["ip", "link", "set", INTERFACE, "up"])
    with tcp_connect(port, CONTROL_PEER) as stream:
        stream.sendall(b"tun-restored")
        assert receive(stream, 12) == b"tun-restored"
        stop(worker)
        try:
            stream.settimeout(1)
            stream.sendall(b"exit-offline")
            assert not stream.recv(65535), "Traffic bypassed the exit node"
        except OSError:
            pass
    print("PASS: TUN down and exit down do not fall back to DIRECT", flush=True)


def trace_packets(cleanup, root):
    listener = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
    listener.bind((INTERFACE, 0))
    listener.settimeout(0.2)
    finished = threading.Event()
    def capture():
        with (root / "tun-packets.jsonl").open("w") as output:
            while not finished.is_set():
                try:
                    packet, address = listener.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if packet[0] >> 4 == 4:
                    protocol, offset = packet[9], (packet[0] & 15) * 4
                    source, destination = packet[12:16], packet[16:20]
                elif packet[0] >> 4 == 6:
                    protocol, offset = packet[6], 40
                    source, destination = packet[8:24], packet[24:40]
                else:
                    continue
                record = {"source": str(ipaddress.ip_address(source)),
                          "destination": str(ipaddress.ip_address(destination)),
                          "protocol": protocol, "packet_type": address[2], "packet": packet.hex()}
                if protocol in (6, 17):
                    record["ports"] = struct.unpack("!HH", packet[offset:offset + 4])
                output.write(json.dumps(record) + "\n")
                output.flush()
    worker = threading.Thread(target=capture, daemon=True)
    worker.start()
    def close():
        finished.set()
        listener.close()
        worker.join(timeout=1)
    cleanup.callback(close)


def exercise(args, root):
    binary = args.xray
    private_key, public_key = key_pair(binary)
    clients = {name: str(uuid.uuid4()) for name in CLIENT_IPS}
    relay_id = str(uuid.uuid4())
    freedom_settings = {"finalRules": [{"action": "allow", "ip": PEERS + [
        CONTROL_PEER, SECOND_CONTROL_PEER]}]}
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=guard.test", "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem")])
    save_config(root, "exit", {
        "log": {"access": str(root / "exit-access.log"), "loglevel": "info"},
        "inbounds": [{"tag": "EXIT", "listen": EXIT_IP, "port": 2443, "protocol": "vless",
                      "settings": {"clients": [{"id": relay_id, "email": "relay@test"}],
                                   "decryption": "none"},
                      "streamSettings": reality(private_key=private_key, network="xhttp")}],
        "outbounds": [{"tag": "DIRECT", "protocol": "freedom", "settings": freedom_settings}]})
    with contextlib.ExitStack() as cleanup:
        worker = launch(cleanup, ["unshare", "--net", sys.executable, "-B", str(Path(__file__).resolve()),
                                 "--exit-worker", str(root), "--xray", args.external_xray or binary], root, "exit-worker",
                        stdin=subprocess.PIPE, text=True)
        wait_for(lambda: worker.poll() is None and os.readlink(f"/proc/{worker.pid}/ns/net") !=
                 os.readlink("/proc/self/ns/net"), "exit network namespace")
        run(["ip", "link", "set", "lo", "up"])
        run(["ip", "link", "add", "ru-test", "type", "veth", "peer", "name", "exit-test"])
        run(["ip", "link", "set", "exit-test", "netns", str(worker.pid)])
        run(["ip", "address", "add", RU_IP + "/30", "dev", "ru-test"])
        run(["ip", "link", "set", "ru-test", "up"])
        run(["ip", "route", "add", "default", "via", EXIT_IP, "dev", "ru-test"])
        for arguments in (["ip", "address", "add", EXIT_IP + "/30", "dev", "exit-test"],
                          ["ip", "link", "set", "exit-test", "up"]):
            run(["nsenter", "-t", str(worker.pid), "-n", *arguments])
        for address in CLIENT_IPS.values():
            run(["ip", "address", "add", address + "/32", "dev", "lo"])
        worker.stdin.write("start\n")
        worker.stdin.flush()
        wait_for(lambda: (root / "exit.ready").exists(), "exit Xray and peers")
        fragment = json.loads((Path(__file__).resolve().parents[2] / "config/xray-tun.fragment.json").read_text())
        fragment["outbounds"][0]["settings"] = freedom_settings
        paths = inspector.Paths(root)
        paths.config.mkdir(parents=True)
        paths.state.write_text(json.dumps({"interface": INTERFACE}))
        network = tun_network.Network(paths.network)
        cleanup.callback(network.clear)
        watcher_code = ("import sys; from pathlib import Path; import inspector; "
                        "paths = inspector.Paths(Path(sys.argv[1])); ")
        if not args.transport_only:
            watcher_code += "inspector.update_queue(paths=paths, check_device=False); "
        watcher_code += "inspector.watch_network(paths)"
        watcher = launch(cleanup, [sys.executable, "-u", "-B", "-c", watcher_code, str(root)], root, "network")
        physical_default = run(["ip", "-4", "-j", "route", "show", "default"]).stdout
        access = root / "ru-access.log"
        eve = root / "eve.json"
        access.touch()
        eve.touch()
        public = {"tag": "PUBLIC_RU_IN_2", "listen": RU_IP, "port": 1443, "protocol": "vless",
                  "settings": {"clients": [{"id": user_id, "email": name + "@test"}
                                           for name, user_id in clients.items()], "decryption": "none"},
                  "streamSettings": reality(private_key=private_key)}
        config = {"log": {"access": str(access), "loglevel": "info"},
                  "dns": {"hosts": {"peer.test": CONTROL_PEER}},
                  "inbounds": [public, *fragment["inbounds"]],
                  "outbounds": [*fragment["outbounds"], outbound(
                      "TO_FREEDOM", EXIT_IP, 2443, relay_id, public_key, "xhttp")],
                  "routing": fragment["routing"]}
        path = save_config(root, "ru", config)
        relay = launch(cleanup, [binary, "run", "-c", str(path)], root, "ru-xray")
        try:
            wait_for(interface_ready, "native Xray TUN")
        except AssertionError as exc:
            raise AssertionError(run(["ip", "-j", "address", "show"]).stdout) from exc
        wait_for(lambda: network.ready(INTERFACE), "automatic IPv4 routing")
        assert run(["ip", "-4", "-j", "route", "show", "default"]).stdout == physical_default
        network.ensure(INTERFACE)
        assert len([rule for rule in tun_network.rules() if rule.get("priority") == tun_network.PRIORITY]) == 1
        inspector.check_interface(INTERFACE)
        if args.trace:
            trace_packets(cleanup, root)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(2)
            probe.bind((CLIENT_IPS["control"], 0))
            probe.connect((RU_IP, 1443))
        sockets = {}
        for number, (name, client_ip) in enumerate(CLIENT_IPS.items()):
            port = 1080 + number
            client_outbound = outbound("RU", RU_IP, 1443, clients[name], public_key)
            client_outbound["sendThrough"] = client_ip
            client_outbound["mux"] = {"enabled": False, "xudpConcurrency": 8}
            client_config = {"log": {"loglevel": "info"}, "inbounds": [{"listen": "127.0.0.1",
                "port": port, "protocol": "socks", "settings": {"udp": True}}],
                "outbounds": [client_outbound]}
            path = save_config(root, "client-" + name, client_config)
            launch(cleanup, [args.external_xray or binary, "run", "-c", str(path)], root, "client-" + name)
            wait_for(lambda: listening("127.0.0.1", port), "client SOCKS")
            sockets[name] = port
        if not args.transport_only:
            original = yaml.safe_load(args.suricata_config.read_text())
            paths.rules.write_text(inspector.RULE)
            paths.yaml.write_text(inspector.dump_config(inspector.configuration(original, paths, eve)))
            suricata_arguments = [args.binary, "-c", str(paths.yaml), "-q", str(inspector.QUEUE),
                                  "--runmode", "workers"]
            suricata = launch(cleanup, suricata_arguments, root, "suricata")
            inspector.wait_ready()
        check_tcp_echo(sockets["control"], b"before-restart")
        previous_index = json.loads(run(["ip", "-j", "link", "show", "dev", INTERFACE]).stdout)[0]["ifindex"]
        stop(relay)
        wait_for(lambda: not interface_ready(), "old TUN removed")
        launch(cleanup, [binary, "run", "-c", str(root / "ru.json")], root, "ru-xray-restarted")
        wait_for(lambda: network.ready(INTERFACE), "automatic routing after Xray restart")
        current_index = json.loads(run(["ip", "-j", "link", "show", "dev", INTERFACE]).stdout)[0]["ifindex"]
        assert previous_index != current_index
        assert watcher.poll() is None
        assert run(["ip", "-4", "-j", "route", "show", "default"]).stdout == physical_default
        check_tcp_echo(sockets["control"], b"after-restart")
        print("PASS: Xray gateway assigns IPv4; routing and rp_filter recover after TUN recreation; "
              "physical default preserved", flush=True)
        with tcp_connect(sockets["control"], CONTROL_PEER) as control:
            control.sendall(b"ordinary-tcp")
            assert receive(control, 12) == b"ordinary-tcp"
            check_tcp_echo(sockets["control"], b"domain-over-tun", "peer.test")
            association, endpoint = socks_request(sockets["udp"], 3, "0.0.0.0", 0)
            cleanup.callback(association.close)
            udp = cleanup.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            udp.settimeout(3)
            check_udp_echo(udp, endpoint, CONTROL_PEER)
            check_udp_echo(udp, endpoint, SECOND_CONTROL_PEER)
            control_association, control_endpoint = socks_request(sockets["control"], 3, "0.0.0.0", 0)
            cleanup.callback(control_association.close)
            control_udp = cleanup.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            control_udp.settimeout(3)
            check_udp_echo(control_udp, control_endpoint, SECOND_CONTROL_PEER)
            print("PASS: native TUN, interface-bound freedom, REALITY/XHTTP, TCP/UDP IPv4", flush=True)
            if args.transport_only:
                check_tun_failure(sockets["control"], worker)
                return
            cfg = {"access": {"type": "file", "path": str(access)},
                   "eve": {"type": "file", "path": str(eve)}, "xray_timezone": "UTC",
                   "audit_path": str(root / "audit.jsonl"), "correlation_buffer_seconds": 0.1,
                   "inspection": {"interface": INTERFACE},
                   "firewall": {"host_network": True, "ban_seconds": 600, "allowlist_cidrs": []}}
            guard.validate(cfg)
            servers = guard.discover_server_ips()
            assert TUN_IP in servers
            firewall = guard.Firewall(cfg["firewall"], servers)
            firewall.allowed_to_ban = lambda address: address in CLIENT_IPS.values()
            firewall.ensure()
            correlator = guard.Correlator(cfg, servers, "enforce", firewall)
            events = queue.Queue()
            followers = [guard.FileFollower(str(access), "access", events),
                         guard.FileFollower(str(root / "ru-xray-restarted.log"), "access", events),
                         guard.FileFollower(str(eve), "eve", events)]
            for follower in followers:
                cleanup.callback(follower.close)
                follower.step()
            for path in (access, root / "ru-xray-restarted.log", eve):
                for line in path.read_text().splitlines():
                    correlator.add_eve(line) if path == eve else correlator.add_access(line)
            def pump():
                for follower in followers:
                    follower.step()
                while not events.empty():
                    kind, line = events.get_nowait()
                    correlator.add_eve(line) if kind == "eve" else correlator.add_access(line)
                correlator.process_pending()
            assert correlator.stats["bans"] == 0
            handshake = b"\x13BitTorrent protocol" + bytes(8) + b"i" * 20 + b"-TEST00-" + b"p" * 12
            for peer in PEERS:
                with tcp_connect(sockets["tcp"], peer) as stream:
                    stream.sendall(handshake)
                    time.sleep(0.1)
                pump()
            wait_for(lambda: correlator.stats["bans"] == 1, "TCP client ban", step=pump)
            control.sendall(b"still-connected")
            assert receive(control, 15) == b"still-connected"
            dht = b"d1:ad2:id20:abcdefghijklmnopqrst6:target20:abcdefghijklmnopqrste1:q9:find_node1:t2:aa1:y1:qe"
            for peer in PEERS:
                for attempt in range(3):
                    udp_send(udp, endpoint, peer, dht)
                    time.sleep(0.1)
                    pump()
            wait_for(lambda: correlator.stats["bans"] == 2, "UDP/XUDP client ban", step=pump)
            control.sendall(b"still-connected")
            assert receive(control, 15) == b"still-connected"
            records = [json.loads(line) for line in Path(cfg["audit_path"]).read_text().splitlines()]
            assert {record["client_ip"] for record in records} == {CLIENT_IPS["tcp"], CLIENT_IPS["udp"]}
            udp_evidence = next(record["evidence"] for record in records if record["client_ip"] == CLIENT_IPS["udp"])
            assert len({item["local"][1] for item in udp_evidence}) == 1, udp_evidence
            assert len({item["peer_ip"] for item in udp_evidence}) == 5, udp_evidence
            assert all(record["ban_seconds"] == 600 and record["result"] == "banned-600s" for record in records)
            rules = run(["nft", "list", "table", "inet", inspector.TABLE]).stdout
            assert "mark" not in rules, rules
            queued = json.loads(run(["nft", "-j", "list", "table", "inet", inspector.TABLE]).stdout)
            counts = {entry["rule"]["chain"]: next(expression["counter"]["packets"]
                      for expression in entry["rule"]["expr"] if "counter" in expression)
                      for entry in queued["nftables"] if "rule" in entry}
            assert set(counts) == {"input", "output"} and all(counts.values()), counts
            assert "relay@test" in (root / "exit-access.log").read_text()
            receipts = [json.loads(line) for line in (root / "received.jsonl").read_text().splitlines()]
            assert all(record["source"] == record["destination"] for record in receipts), receipts
            assert not any(b"BitTorrent protocol" in bytes.fromhex(record["payload"])
                           for record in receipts), receipts
            delivered_dht = {peer: sum(record["destination"] == peer and
                             bytes.fromhex(record["payload"]) == dht for record in receipts) for peer in PEERS}
            assert all(count < 3 for count in delivered_dht.values()), delivered_dht
            print("PASS: real nDPI drops TCP BitTorrent and DHT; original client IPs banned for 600s; "
                  "five UDP peers share one local port; control client survives", flush=True)
            state = json.loads(run(["nft", "-j", "list", "set", "inet", guard.TABLE, "clients_v4"]).stdout)
            stop(suricata)
            check_tcp_blocked(sockets["control"])
            launch(cleanup, suricata_arguments, root, "suricata-restarted")
            inspector.wait_ready()
            check_tcp_echo(sockets["control"], b"queue-restored")
            print("PASS: missing NFQUEUE listener fails closed; Suricata restart restores traffic", flush=True)
            check_tun_failure(sockets["control"], worker)
            (root / "result.json").write_text(json.dumps({"stats": dict(correlator.stats),
                "bans": records, "nft_bans": state, "queue_packets": counts,
                "fail_closed": ["nfqueue-listener-down", "tun-down", "exit-down"],
                "automatic_ipv4": {"tun_recreated": True, "physical_default_preserved": True},
                "xray": run([binary, "version"]).stdout}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xray", default="/usr/local/bin/xray")
    parser.add_argument("--external-xray", help="Use another Xray binary for clients/exit to test mixed versions")
    parser.add_argument("--binary", help="Suricata 8+ binary with nDPI and NFQUEUE")
    parser.add_argument("--suricata-config", type=Path)
    parser.add_argument("--transport-only", action="store_true")
    parser.add_argument("--exit-worker", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--trace", action="store_true", help="Record test TUN packets in the output directory")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        parser.error("Run as root with unshare --net; host firewall access is forbidden")
    if args.exit_worker:
        exit_worker(args)
        return
    if not args.transport_only and (not args.binary or not args.suricata_config):
        parser.error("Provide --binary and --suricata-config, or use --transport-only")
    with contextlib.ExitStack() as cleanup:
        if args.output:
            root = args.output.resolve()
            root.mkdir(mode=0o700)
        else:
            root = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="xray-tun-test-")))
        print(f"TUN test artifacts: {root}", flush=True)
        try:
            exercise(args, root)
        except BaseException:
            for path in root.glob("*.log"):
                print(f"\n{path.name}:\n" + "\n".join(path.read_text(errors="replace").splitlines()[-20:]),
                      file=sys.stderr)
            raise


if __name__ == "__main__":
    main()
