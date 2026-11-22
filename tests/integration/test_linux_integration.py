#!/usr/bin/env python3
"""Run in a private network namespace; see tests/README.md for commands."""
import datetime as dt
import json
import os
import queue
import socket
import sys
import tempfile
from pathlib import Path
from unittest import mock

import guard as g


def main(xudp=False):
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise SystemExit("Refusing host firewall access. Run in a separate network namespace.")
    g.run(["ip", "link", "set", "lo", "up"])
    server_ip = "192.0.2.10"
    client_ip = "203.0.113.20"
    control_ip = "203.0.113.30"
    for ip in (server_ip, client_ip, control_ip):
        g.run(["ip", "address", "add", ip + "/32", "dev", "lo"])

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as listener, \
         socket.socket(socket.AF_INET, socket.SOCK_STREAM) as other_listener, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_server, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other_udp_server, \
         socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client, \
         socket.socket(socket.AF_INET, socket.SOCK_STREAM) as other_client, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_client, \
         socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as xudp_socket, \
         tempfile.TemporaryDirectory(prefix="guard-integration-") as folder:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        listener.bind(("::", 0))
        listener.listen(5)
        listener.settimeout(1)
        port = listener.getsockname()[1]
        other_listener.bind((server_ip, 0))
        other_listener.listen(5)
        other_port = other_listener.getsockname()[1]
        udp_server.bind((server_ip, port))
        udp_server.settimeout(.3)
        other_udp_server.bind((server_ip, other_port))
        other_udp_server.settimeout(.3)
        client.bind((client_ip, 0))
        client.settimeout(1)
        client.connect((server_ip, port))
        accepted, _ = listener.accept()
        other_client.bind((client_ip, 0))
        other_client.settimeout(1)
        other_client.connect((server_ip, other_port))
        other_accepted, _ = other_listener.accept()
        udp_client.bind((client_ip, 0))
        udp_client.sendto(b"before", (server_ip, port))
        assert udp_server.recv(100) == b"before"
        udp_client.sendto(b"other-before", (server_ip, other_port))
        assert other_udp_server.recv(100) == b"other-before"
        xudp_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        xudp_socket.bind(("::", 0))
        egress_port = xudp_socket.getsockname()[1]
        try:
            root = Path(folder)
            access = root / "access.log"
            eve = root / "eve.json"
            access.touch()
            eve.touch()
            cfg = {
                "xray_timezone": "UTC",
                "access": {"type": "file", "path": str(access)},
                "eve": {"type": "file", "path": str(eve)},
                "correlation_buffer_seconds": 0,
                "min_distinct_flows": 5, "min_distinct_peers": 5,
                "window_seconds": 300, "audit_path": str(root / "audit.jsonl"),
                "firewall": {"host_network": True, "ban_seconds": 600, "allowlist_cidrs": []},
            }
            g.validate(cfg)
            servers = {server_ip}
            fw = g.Firewall(cfg["firewall"], servers)
            # Use documentation addresses inside this private namespace;
            # public-address validation has its own unit coverage.
            fw.allowed_to_ban = lambda ip: ip == client_ip
            fw.ensure()
            # Simulate a firewall reload after guard startup.
            g.run(["nft", "delete", "table", "inet", g.TABLE])
            correlator = g.Correlator(cfg, servers, "enforce", fw)
            out = queue.Queue(maxsize=2)
            followers = [g.follower(cfg["access"], "access", out),
                         g.follower(cfg["eve"], "eve", out)]
            try:
                for f in followers:
                    f.step()
                now = dt.datetime.now(dt.timezone.utc)
                started = now if xudp else now - dt.timedelta(seconds=95)
                stamp = started.strftime("%Y/%m/%d %H:%M:%S.%f")
                if xudp:
                    # One real dual-stack UDP socket, one initial access record.
                    # Later peers have no individual access entries.
                    with access.open("a") as af:
                        af.write(f"{stamp} [Info] [20001] proxy/freedom: connection opened to "
                                 f"udp:198.51.100.10:6881, local endpoint [::]:{egress_port}, "
                                 "remote endpoint 198.51.100.10:6881\n")
                        af.write(f"{stamp} from tcp:{client_ip}:50000 accepted udp:198.51.100.10:6881 "
                                 "[in >> direct] email: integration\n")
                    followers[0].step()
                    while not out.empty():
                        _, line = out.get_nowait()
                        correlator.add_access(line)
                    correlator.process_pending()
                    assert correlator.stats["udp_socket_bindings"] == 1
                    assert g.read_udp_sockets()[("::", egress_port)] == {
                        correlator.udp.entries[("::", egress_port)]["inode"]}
                    now += dt.timedelta(seconds=95)
                with access.open("a") as af, eve.open("a") as ef:
                    for i in range(5):
                        peer = f"198.51.100.{i+1}"
                        if not xudp:
                            af.write(f"{stamp} from tcp:{client_ip}:50000 accepted udp:{peer}:{31000+i} "
                                     "[in >> direct] email: integration\n")
                        ef.write(json.dumps({
                            "event_type": "alert", "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
                            "alert": {"action": "blocked", "signature_id": 9100001},
                            "src_ip": server_ip, "src_port": egress_port if xudp else 40000+i,
                            "dest_ip": peer, "dest_port": 31000+i,
                            "proto": "UDP", "flow_id": i,
                            "flow": {"start": started.strftime("%Y-%m-%dT%H:%M:%S.%f%z")},
                        }) + "\n")
                for _ in range(12):
                    for f in followers:
                        f.step()
                    while not out.empty():
                        source, line = out.get_nowait()
                        if source == "access":
                            correlator.add_access(line)
                        else:
                            correlator.add_eve(line)
                    with mock.patch.object(g.time, "time", return_value=now.timestamp()):
                        correlator.process_pending()
                assert correlator.stats["matched"] == 5
                assert correlator.stats["matched_by_udp_socket"] == (5 if xudp else 0)
                assert correlator.stats["bans"] == 1
                state = json.loads(g.run(
                    ["nft", "-j", "list", "set", "inet", g.TABLE, "clients_v4"]).stdout)
                entry = next(item["set"] for item in state["nftables"] if "set" in item)
                element = entry["elem"][0]["elem"]
                assert element["val"] == client_ip
                assert element.get("timeout", entry["timeout"]) == 600
                assert 590 < element["expires"] <= 600
                if xudp:
                    xudp_socket.close()
                    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as replacement:
                        replacement.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                        replacement.bind(("::", egress_port))
                        assert not correlator.evaluate({
                            "ts": now.timestamp(), "flow_start_ts": now.timestamp(), "proto": "UDP",
                            "local": (server_ip, egress_port), "peer": ("198.51.100.6", 31006),
                            "flow": "recycled-socket", "sid": 9100001})
                expr = f"dst {client_ip}"
                assert not g.run(["ss", "-H", "-n", "-t", "state", "established", expr]).stdout.strip()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as retry:
                    retry.bind((client_ip, 0))
                    retry.settimeout(.3)
                    try:
                        retry.connect((server_ip, port))
                    except socket.timeout:
                        pass
                    else:
                        raise AssertionError("Banned IP can still connect over TCP")
                udp_client.sendto(b"blocked", (server_ip, port))
                try:
                    udp_server.recv(100)
                except socket.timeout:
                    pass
                else:
                    raise AssertionError("Banned IP can still send UDP")
                # No port list exists: a second TCP/UDP service must be blocked too.
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as retry:
                    retry.bind((client_ip, 0))
                    retry.settimeout(.3)
                    try:
                        retry.connect((server_ip, other_port))
                    except socket.timeout:
                        pass
                    else:
                        raise AssertionError("Banned IP can still connect to another TCP port")
                udp_client.sendto(b"other-blocked", (server_ip, other_port))
                try:
                    other_udp_server.recv(100)
                except socket.timeout:
                    pass
                else:
                    raise AssertionError("Banned IP can still send to another UDP port")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as control, \
                     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control_udp:
                    control.bind((control_ip, 0))
                    control.settimeout(1)
                    control.connect((server_ip, port))
                    control_accepted, _ = listener.accept()
                    control_accepted.close()
                    control_udp.bind((control_ip, 0))
                    control_udp.sendto(b"allowed", (server_ip, port))
                    assert udp_server.recv(100) == b"allowed"
                source = "XUDP socket + live inode, recycled port rejected" if xudp else "direct peer access"
                print(f"PASS: {source}; five flows classified 95s after start -> 600s ban; deleted table recreated; TCP torn down; "
                      "TCP/UDP blocked on two different ports; other client remains connected")
            finally:
                for f in followers:
                    f.close()
        finally:
            accepted.close()
            other_accepted.close()


if __name__ == "__main__":
    main(xudp="--xudp" in sys.argv[1:])
