#!/usr/bin/env python3
"""Exercise real Marzban and systemd only inside the disposable Docker test host."""
import argparse
import contextlib
import ctypes
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import test_linux_tun as transport


ROOT = Path(__file__).resolve().parents[2]
DATA = Path("/var/lib/marzban-test")
NEW = "/fixtures/new/xray"
OLD = "/fixtures/old/xray"
CLIENTS = {"tcp": "11.0.0.20", "udp": "11.0.0.21", "control": "11.0.0.30"}
UNITS = ["xray-connection-guard.service", "xray-ndpi.service",
         "xray-connection-guard-queue.service"]
CONTEXT = ssl._create_unverified_context()


def command(arguments, *, check=True, timeout=180):
    result = subprocess.run(list(map(str, arguments)), capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{arguments}:\n{result.stdout}\n{result.stderr}")
    return result


def manage(*arguments, check=True):
    result = command(["bash", ROOT / "manage.sh", *arguments], check=check)
    print(result.stdout, end="", flush=True)
    return result


def wait(predicate, label, timeout=45):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (OSError, ValueError, RuntimeError, EOFError) as error:
            last_error = error
        time.sleep(0.2)
    raise AssertionError(f"Timed out: {label}; last error: {last_error}")


@contextlib.contextmanager
def namespace(pid):
    original = os.open("/proc/thread-self/ns/net", os.O_RDONLY)
    target = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    library = ctypes.CDLL(None, use_errno=True)
    try:
        if library.setns(target, 0):
            raise OSError(ctypes.get_errno(), "setns")
        yield
    finally:
        if library.setns(original, 0):
            raise OSError(ctypes.get_errno(), "restore setns")
        os.close(target)
        os.close(original)


class Panel:
    def __init__(self):
        self.token = None

    def request(self, path, payload=None, method=None):
        headers = {}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if isinstance(payload, bytes):
            body = payload
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(payload).encode() if payload is not None else None
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request("https://127.0.0.1:8000/api" + path,
                                         data=body, headers=headers, method=method)
        with urllib.request.urlopen(request, context=CONTEXT, timeout=15) as response:
            return json.load(response)

    def login(self):
        self.token = self.request("/admin/token", urllib.parse.urlencode({
            "username": "guardtest", "password": "disposable-test-password"}).encode())["access_token"]
        return True


class ManagementMonitor:
    def __init__(self, pid):
        self.pid = pid
        self.phase = "startup"
        self.finished = threading.Event()
        self.failures = []
        self.samples = 0
        self.worker = threading.Thread(target=self.loop, daemon=True)

    def probe(self, service):
        if service == "ssh":
            with socket.create_connection((transport.RU_IP, 22), timeout=0.7,
                                          source_address=(CLIENTS["control"], 0)) as stream:
                assert stream.recv(128).startswith(b"SSH-"), "SSH banner missing"
            return
        connection = http.client.HTTPSConnection(transport.RU_IP, 8000, timeout=0.7,
                         source_address=(CLIENTS["control"], 0), context=CONTEXT)
        try:
            connection.request("GET", "/dashboard/")
            assert connection.getresponse().status < 500
        finally:
            connection.close()

    def loop(self):
        with namespace(self.pid):
            while not self.finished.is_set():
                for service in ("ssh", "panel"):
                    phase = self.phase
                    try:
                        self.probe(service)
                        self.samples += 1
                    except (OSError, AssertionError, http.client.HTTPException) as error:
                        self.failures.append({"phase": phase, "service": service, "error": str(error)})
                self.finished.wait(0.2)

    def start(self):
        with namespace(self.pid):
            for service in ("ssh", "panel"):
                self.probe(service)
        self.worker.start()

    def stop(self):
        self.finished.set()
        self.worker.join(timeout=5)


def snapshot():
    return {"addresses": json.loads(command(["ip", "-j", "address"]).stdout),
            "rules": json.loads(command(["ip", "-4", "-j", "rule"]).stdout),
            "default": json.loads(command(["ip", "-4", "-j", "route", "show", "default"]).stdout),
            "nft": command(["nft", "list", "ruleset"]).stdout}


def restore_default(routes):
    command(["ip", "route", "del", "default", "via", "192.0.2.5", "dev", "client-test", "metric", "100"],
            check=False)
    for route in routes:
        arguments = ["ip", "route", "add", "default", "via", route["gateway"], "dev", route["dev"]]
        if route.get("metric"):
            arguments.extend(["metric", str(route["metric"])])
        command(arguments, check=False)


def network_setup(cleanup, output, state):
    command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=guard.test", "-keyout", output / "key.pem", "-out", output / "cert.pem"])
    transport.save_config(output, "exit", {
        "log": {"loglevel": "info"},
        "inbounds": [{"tag": "EXIT", "listen": transport.EXIT_IP, "port": 2443,
                      "protocol": "vless", "settings": {"clients": [{"id": state["relay_id"],
                      "email": "relay@test"}], "decryption": "none"},
                      "streamSettings": transport.reality(private_key=state["private"], network="xhttp")}],
        "outbounds": [{"tag": "DIRECT", "protocol": "freedom", "settings": {
            "finalRules": [{"action": "allow", "ip": transport.PEERS + [
                transport.CONTROL_PEER, transport.SECOND_CONTROL_PEER]}]}}]})
    (output / "exit.ready").unlink(missing_ok=True)
    exit_worker = transport.launch(cleanup, ["unshare", "--net", sys.executable, "-B",
        str(ROOT / "tests/integration/test_linux_tun.py"), "--exit-worker", str(output), "--xray", NEW],
        output, "exit-worker", stdin=subprocess.PIPE, text=True)
    client_worker = transport.launch(cleanup, ["unshare", "--net", "sleep", "infinity"], output, "clients")
    for worker in (exit_worker, client_worker):
        wait(lambda: os.readlink(f"/proc/{worker.pid}/ns/net") != os.readlink("/proc/self/ns/net"),
             "private worker namespace")
    for local, remote, address, peer_address, worker in (
            ("ru-test", "exit-test", transport.RU_IP, transport.EXIT_IP, exit_worker),
            ("client-test", "client-peer", "192.0.2.6", "192.0.2.5", client_worker)):
        command(["ip", "link", "add", local, "type", "veth", "peer", "name", remote])
        cleanup.callback(command, ["ip", "link", "del", local], check=False)
        command(["ip", "link", "set", remote, "netns", str(worker.pid)])
        command(["ip", "address", "add", address + "/30", "dev", local])
        command(["ip", "link", "set", local, "up"])
        for arguments in (["ip", "link", "set", "lo", "up"],
                          ["ip", "address", "add", peer_address + "/30", "dev", remote],
                          ["ip", "link", "set", remote, "up"]):
            command(["nsenter", "-t", str(worker.pid), "-n", *arguments])
    with namespace(client_worker.pid):
        for address in CLIENTS.values():
            command(["ip", "address", "add", address + "/32", "dev", "lo"])
        command(["ip", "route", "add", "default", "via", "192.0.2.6"])
    previous = json.loads(command(["ip", "-4", "-j", "route", "show", "default"]).stdout)
    for route in previous:
        command(["ip", "route", "del", "default", "via", route["gateway"], "dev", route["dev"]])
    command(["ip", "route", "add", "default", "via", "192.0.2.5", "dev", "client-test", "metric", "100"])
    cleanup.callback(restore_default, previous)
    exit_worker.stdin.write("start\n")
    exit_worker.stdin.flush()
    wait(lambda: (output / "exit.ready").exists(), "exit Xray")
    return exit_worker, client_worker


def start_panel(image, binary, config, output):
    command(["docker", "rm", "-f", "marzban"], check=False)
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "xray_config.json").write_text(json.dumps(config))
    for filename in ("cert.pem", "key.pem"):
        shutil.copyfile(output / filename, DATA / filename)
    command(["docker", "run", "-d", "--name", "marzban", "--restart", "unless-stopped",
             "--network", "host", "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
             *(argument for hostname in ("api4.ipify.org", "api6.ipify.org", "ipv4.icanhazip.com",
                  "ipv6.icanhazip.com", "ifconfig.io") for argument in ("--add-host", hostname + ":127.0.0.1")),
             "-v", str(DATA) + ":/var/lib/marzban", "-v", binary + ":/usr/local/bin/xray:ro",
             "-e", "SQLALCHEMY_DATABASE_URL=sqlite:////var/lib/marzban/db.sqlite3",
             "-e", "XRAY_JSON=/var/lib/marzban/xray_config.json", "-e", "SUDO_USERNAME=guardtest",
             "-e", "SUDO_PASSWORD=disposable-test-password", "-e", "UVICORN_HOST=0.0.0.0",
             "-e", "UVICORN_SSL_CERTFILE=/var/lib/marzban/cert.pem",
             "-e", "UVICORN_SSL_KEYFILE=/var/lib/marzban/key.pem",
             "-e", "UVICORN_SSL_CA_TYPE=private", image])
    panel = Panel()
    wait(panel.login, "Marzban API", timeout=90)
    return panel


def client_setup(cleanup, pid, output, state):
    ports = {}
    for number, (name, address) in enumerate(CLIENTS.items()):
        outbound = transport.outbound("RU", transport.RU_IP, 1443, state["users"][name], state["public"])
        outbound["sendThrough"] = address
        outbound["mux"] = {"enabled": False, "xudpConcurrency": 8}
        port = 1080 + number
        path = transport.save_config(output, "client-" + name, {
            "log": {"loglevel": "info"}, "inbounds": [{"listen": "127.0.0.1", "port": port,
            "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}], "outbounds": [outbound]})
        transport.launch(cleanup, ["nsenter", "-t", str(pid), "-n", OLD, "run", "-c", str(path)],
                         output, "client-" + name)
        with namespace(pid):
            wait(lambda: transport.listening("127.0.0.1", port), "client SOCKS")
        ports[name] = port
    return ports


def make_config(state, tun=False):
    inbound_stream = transport.reality(private_key=state["private"], network="tcp")
    inbound_stream["realitySettings"]["publicKey"] = state["public"]
    config = {"log": {"access": "/var/lib/marzban/access.log", "error": "/var/lib/marzban/access.log",
                      "loglevel": "info", "maskAddress": ""},
              "dns": {"hosts": {"peer.test": transport.CONTROL_PEER}},
              "inbounds": [{"tag": "PUBLIC_RU_IN_2", "listen": transport.RU_IP, "port": 1443,
                  "protocol": "vless", "settings": {"clients": [], "decryption": "none"},
                  "streamSettings": inbound_stream}],
              "outbounds": [transport.outbound("TO_FREEDOM", transport.EXIT_IP, 2443,
                  state["relay_id"], state["public"], "xhttp")],
              "routing": {"rules": [{"inboundTag": ["PUBLIC_RU_IN_2"], "outboundTag": "TO_FREEDOM"}]}}
    if tun:
        fragment = json.loads((ROOT / "config/xray-tun.fragment.json").read_text())
        config["inbounds"].extend(fragment["inbounds"])
        config["outbounds"].extend(fragment["outbounds"])
        config["outbounds"][-1]["settings"] = {"finalRules": [{"action": "allow",
            "ip": transport.PEERS + [transport.CONTROL_PEER, transport.SECOND_CONTROL_PEER]}]}
        config["routing"] = fragment["routing"]
    return config


def ordinary_traffic(pid, ports):
    with namespace(pid):
        transport.check_tcp_echo(ports["control"], b"ordinary-ipv4")
        transport.check_tcp_echo(ports["control"], b"ordinary-domain", address="peer.test")
        association, endpoint = transport.socks_request(ports["control"], 3,
                                    transport.SECOND_CONTROL_PEER, transport.PEER_PORT)
        with association, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(3)
            for address in (transport.SECOND_CONTROL_PEER, transport.CONTROL_PEER,
                            transport.SECOND_CONTROL_PEER):
                transport.check_udp_echo(stream, endpoint, address)


def audit_records():
    path = Path("/var/log/xray-connection-guard/audit.jsonl")
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def live_units():
    return command(["systemctl", "is-active", *UNITS], check=False).stdout.split() == ["active"] * 3


def test_current_core(panel, pid, ports, state, report):
    monitor = ManagementMonitor(pid)
    monitor.start()
    baseline = snapshot()["default"]
    def passed(label):
        report["tests"].append(label)
        print("PASS: " + label, flush=True)
    try:
        monitor.phase = "repeated-enable"
        manage("enable")
        manage("enable")
        routes = transport.tun_network.routes()
        assert len(routes) == 1 and routes[0]["prefsrc"] == transport.TUN_IP, routes
        assert len([rule for rule in transport.tun_network.rules() if rule.get("priority") == 14817]) == 1
        config = json.loads(Path("/etc/xray-connection-guard/config.json").read_text())
        assert config["access"] == {"type": "docker", "container": "marzban",
                                    "path": "/var/lib/marzban/access.log"}, config["access"]
        ordinary_traffic(pid, ports)
        passed("Repeated enable is idempotent; Docker log discovery, TCP, UDP peer changes and DNS work")

        monitor.phase = "core-restart"
        previous = json.loads(command(["ip", "-j", "link", "show", "dev", "xray-guard"]).stdout)[0]["ifindex"]
        panel.request("/core/restart", {}, method="POST")
        wait(lambda: json.loads(command(["ip", "-j", "link", "show", "dev", "xray-guard"]).stdout)[0]["ifindex"] != previous,
             "TUN recreation")
        wait(lambda: transport.tun_network.Network(Path("/run/xray-connection-guard/tun-network.json")).ready("xray-guard"),
             "automatic route recovery")
        ordinary_traffic(pid, ports)
        passed("Marzban core restart recreates TUN and restores IPv4 routing without manual commands")

        monitor.phase = "marzban-restart"
        command(["docker", "restart", "marzban"])
        wait(panel.login, "Marzban container restart", timeout=90)
        wait(lambda: transport.tun_network.Network(Path("/run/xray-connection-guard/tun-network.json")).ready("xray-guard"),
             "container TUN recovery")
        ordinary_traffic(pid, ports)
        monitor.phase = "after-marzban-restart"
        passed("Marzban container restart restores the inspected TCP/UDP path; SSH stays reachable")

        monitor.phase = "ip-bans"
        handshake = b"\x13BitTorrent protocol" + bytes(8) + b"i" * 20 + b"-TEST00-" + b"p" * 12
        dht = b"d1:ad2:id20:abcdefghijklmnopqrst6:target20:abcdefghijklmnopqrste1:q9:find_node1:t2:aa1:y1:qe"
        with namespace(pid):
            association, endpoint = transport.socks_request(ports["udp"], 3,
                                                transport.CONTROL_PEER, transport.PEER_PORT)
            with association, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
                stream.settimeout(3)
                transport.check_udp_echo(stream, endpoint, transport.CONTROL_PEER)
                for peer in transport.PEERS:
                    with transport.tcp_connect(ports["tcp"], peer) as connection:
                        connection.sendall(handshake)
                        time.sleep(0.1)
                wait(lambda: any(record["client_ip"] == CLIENTS["tcp"] and record["result"] == "banned-600s"
                                 for record in audit_records()), "real TCP ban")
                for peer in transport.PEERS:
                    for attempt in range(3):
                        transport.udp_send(stream, endpoint, peer, dht)
                        time.sleep(0.15)
                wait(lambda: any(record["client_ip"] == CLIENTS["udp"] and record["result"] == "banned-600s"
                                 for record in audit_records()), "real UDP ban")
            transport.check_tcp_blocked(ports["tcp"])
            transport.check_tcp_echo(ports["control"], b"unbanned-control")
            try:
                with socket.create_connection((transport.RU_IP, 22), timeout=0.5,
                                              source_address=(CLIENTS["tcp"], 0)) as blocked:
                    assert not blocked.recv(128), "An IP ban did not cover SSH"
            except OSError:
                pass
        records = [record for record in audit_records() if record["result"] == "banned-600s"]
        assert {record["client_ip"] for record in records} == {CLIENTS["tcp"], CLIENTS["udp"]}, records
        udp = next(record for record in records if record["client_ip"] == CLIENTS["udp"])
        assert len({entry["local"][1] for entry in udp["evidence"]}) == 1, udp
        report["bans"] = records
        report["nft_bans"] = json.loads(command(["nft", "-j", "list", "set", "inet", "xray_client_ban", "clients_v4"]).stdout)
        command(["systemctl", "restart", UNITS[0]])
        assert CLIENTS["tcp"] in command(["nft", "list", "set", "inet", "xray_client_ban", "clients_v4"]).stdout
        passed("Real guard service bans both original client IPs for 600s; UDP uses one socket; control and SSH survive")

        monitor.phase = "off-monitor"
        manage("off")
        assert command(["systemctl", "is-active", UNITS[1]]).stdout.strip() == "active"
        assert command(["nft", "list", "table", "inet", "xray_client_ban"], check=False).returncode != 0
        manage("monitor")
        with namespace(pid):
            for peer in transport.PEERS:
                with transport.tcp_connect(ports["tcp"], peer) as connection:
                    connection.sendall(handshake)
                    time.sleep(0.1)
        wait(lambda: any(record["result"] == "monitor-only" for record in audit_records()), "monitor incident")
        assert command(["nft", "list", "table", "inet", "xray_client_ban"], check=False).returncode != 0
        passed("off clears only IP bans; monitor keeps Suricata blocking but does not apply IP bans")
        manage("enable")

        for unit in (UNITS[1], UNITS[2]):
            monitor.phase = "stop-" + unit
            command(["systemctl", "stop", unit])
            if unit == UNITS[1]:
                with namespace(pid):
                    transport.check_tcp_blocked(ports["control"])
            else:
                assert command(["nft", "list", "table", "inet", "xray_guard_inspect"], check=False).returncode != 0
                with namespace(pid):
                    try:
                        transport.check_tcp_echo(ports["control"], b"queue-stop-negative-probe")
                        report["explicit_queue_stop"] = "traffic can pass without inspection; restore the profile first"
                    except (OSError, EOFError):
                        report["explicit_queue_stop"] = "traffic blocked; explicit stop still removes the filter"
            assert snapshot()["default"] == baseline
            manage("enable")
            ordinary_traffic(pid, ports)
            passed(f"Stopping {unit}: documented stop semantics; enable restores services and preserves the physical default")

        monitor.phase = "queue-crash"
        command(["systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", UNITS[2]])
        command(["systemctl", "stop", UNITS[1]])
        time.sleep(0.3)
        assert command(["nft", "list", "table", "inet", "xray_guard_inspect"], check=False).returncode == 0
        with namespace(pid):
            transport.check_tcp_blocked(ports["control"])
        manage("enable")
        ordinary_traffic(pid, ports)
        passed("Queue watcher crash retains fail-closed NFQUEUE rules; explicit enable recovers all services")

        monitor.phase = "missing-gateway"
        broken = make_config(state, tun=True)
        broken["inbounds"][1]["settings"].pop("gateway")
        panel.request("/core/config", broken, method="PUT")
        wait(transport.interface_ready, "TUN without gateway")
        with namespace(pid):
            transport.check_tcp_blocked(ports["control"])
        assert snapshot()["default"] == baseline
        panel.request("/core/config", make_config(state, tun=True), method="PUT")
        wait(lambda: transport.tun_network.Network(Path("/run/xray-connection-guard/tun-network.json")).ready("xray-guard"),
             "gateway restoration")
        ordinary_traffic(pid, ports)
        passed("Missing gateway breaks only the selected proxy path; restoring the profile recovers routing automatically")

        monitor.phase = "unsafe-global-default"
        broken = make_config(state, tun=True)
        broken["inbounds"][1]["settings"]["autoSystemRoutingTable"] = ["0.0.0.0/0"]
        panel.request("/core/config", broken, method="PUT")
        wait(lambda: any(route["dev"] == "xray-guard" for route in snapshot()["default"]), "unsafe global TUN default")
        time.sleep(2)
        assert any(failure["phase"] == "unsafe-global-default" and failure["service"] == "ssh"
                   for failure in monitor.failures), monitor.failures
        report["unsafe_global_default"] = snapshot()["default"]
        panel.request("/core/config", make_config(state, tun=True), method="PUT")
        wait(lambda: snapshot()["default"] == baseline, "removal of unsafe global default")
        wait(lambda: transport.tun_network.Network(Path("/run/xray-connection-guard/tun-network.json")).ready("xray-guard"),
             "recovery after unsafe profile")
        time.sleep(1)
        monitor.phase = "rollback"
        ordinary_traffic(pid, ports)
        passed("Negative test: global autoSystemRoutingTable can cut off SSH; reverting the profile restores access")

        panel.request("/core/config", make_config(state), method="PUT")
        manage("off")
        command(["systemctl", "disable", "--now", UNITS[1], UNITS[2]])
        command(["python3", "/opt/xray-connection-guard/inspector.py", "queue-off"])
        assert not transport.tun_network.routes()
        assert not any(rule.get("priority") == 14817 for rule in transport.tun_network.rules())
        assert command(["nft", "list", "table", "inet", "xray_guard_inspect"], check=False).returncode != 0
        assert snapshot()["default"] == baseline
        with namespace(pid):
            transport.check_tcp_echo(ports["control"], b"after-full-rollback")
        passed("Full rollback removes owned routes, policy rule and NFQUEUE; the original relay path still works")
        panel.request("/core/config", make_config(state, tun=True), method="PUT")
        manage("enable", "--inspection-interface", "xray-guard", "--container", "marzban")
        command(["systemctl", "enable", "docker"])
        ordinary_traffic(pid, ports)
    finally:
        monitor.stop()
        report["management"] = {"successful_samples": monitor.samples, "failures": monitor.failures}
    unexpected = [failure for failure in monitor.failures if failure["phase"] != "unsafe-global-default"
                  and not (failure["phase"] == "marzban-restart" and failure["service"] == "panel")]
    assert not unexpected, unexpected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("/results"))
    parser.add_argument("--image", default="gozargah/marzban:latest")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--suricata-config", required=True)
    args = parser.parse_args()
    if not os.environ.get("XRAY_GUARD_ISOLATED_HOST") or Path("/proc/1/comm").read_text().strip() != "systemd":
        parser.error("Only run in the disposable Docker test host with real systemd")
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    report = {"systemd": command(["systemctl", "--version"]).stdout.splitlines()[0], "tests": []}
    private, public = transport.key_pair(NEW)
    state = {"private": private, "public": public, "relay_id": str(uuid.uuid4()),
             "users": {name: str(uuid.uuid4()) for name in CLIENTS}}
    (output.parent / "test-state.json").write_text(json.dumps(state))
    os.environ["SURICATA_BIN"] = args.binary
    os.environ["SURICATA_CONFIG"] = args.suricata_config
    binary, base, config = transport.inspector.discover(transport.inspector.Paths())
    transport.inspector.preflight(binary, config)
    try:
        with contextlib.ExitStack() as cleanup:
            command(["systemctl", "stop", *UNITS], check=False)
            command(["docker", "rm", "-f", "marzban"], check=False)
            for filename in ("db.sqlite3", "db.sqlite3-shm", "db.sqlite3-wal"):
                (DATA / filename).unlink(missing_ok=True)
            Path("/var/log/xray-connection-guard/audit.jsonl").unlink(missing_ok=True)
            exit_worker, client_worker = network_setup(cleanup, output, state)
            command(["systemctl", "start", "ssh"])
            print("Starting real Marzban with Xray 26.3.27", flush=True)
            panel = start_panel(args.image, OLD, make_config(state), output)
            report["old_core"] = panel.request("/core")
            for name, user_id in state["users"].items():
                panel.request("/user", {"username": "guard" + name,
                    "proxies": {"vless": {"id": user_id}}, "inbounds": {"vless": ["PUBLIC_RU_IN_2"]},
                    "expire": 0, "data_limit": 0})
            ports = client_setup(cleanup, client_worker.pid, output, state)
            with namespace(client_worker.pid):
                transport.check_tcp_echo(ports["control"], b"before-tun")
            monitor = ManagementMonitor(client_worker.pid)
            monitor.start()
            cleanup.callback(monitor.stop)
            baseline = snapshot()["default"]
            manage("install")
            monitor.phase = "old-core-tun"
            print("Applying TUN through Marzban API on Xray 26.3.27", flush=True)
            panel.request("/core/config", make_config(state, tun=True), method="PUT")
            wait(transport.interface_ready, "old native TUN")
            old_address = command(["ip", "-4", "-j", "address", "show", "dev", "xray-guard"]).stdout
            report["old_tun"] = json.loads(old_address)
            assert not any(device["addr_info"] for device in report["old_tun"]), old_address
            result = manage("enable", "--inspection-interface", "xray-guard", "--container", "marzban", check=False)
            report["old_enable"] = {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
            assert result.returncode != 0, "Old core unexpectedly configured a gateway"
            report["tests"].append("26.3.27 ignores gateway; enable fails without changing physical default")
            assert snapshot()["default"] == baseline
            monitor.stop()
            report["legacy_management"] = {"samples": monitor.samples, "failures": monitor.failures}
            assert not monitor.failures, monitor.failures
            command(["journalctl", "-u", UNITS[2], "--no-pager"])
            (output / "old-queue.log").write_text(command(["journalctl", "-u", UNITS[2], "--no-pager"]).stdout)
            command(["systemctl", "stop", *UNITS], check=False)
            print("Starting real Marzban with Xray 26.11.9", flush=True)
            panel = start_panel(args.image, NEW, make_config(state, tun=True), output)
            report["new_core"] = panel.request("/core")
            manage("enable", "--inspection-interface", "xray-guard", "--container", "marzban")
            assert command(["systemctl", "is-active", *UNITS]).stdout.split() == ["active"] * 3
            with namespace(client_worker.pid):
                transport.check_tcp_echo(ports["control"], b"new-core-tun")
            assert snapshot()["default"] == baseline
            report["tests"].append("26.11.9 assigns gateway; real systemd services and Marzban TCP path are healthy")
            print("PASS: Docker Marzban version comparison and real systemd startup", flush=True)
            test_current_core(panel, client_worker.pid, ports, state, report)
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        report["final_network"] = snapshot()
        for name, arguments in {
                "systemd.log": ["journalctl", "-u", UNITS[0], "-u", UNITS[1], "-u", UNITS[2], "--no-pager"],
                "marzban.log": ["docker", "logs", "marzban"]}.items():
            result = command(arguments, check=False)
            (output / name).write_text(result.stdout + result.stderr)
        (output / "result.json").write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
