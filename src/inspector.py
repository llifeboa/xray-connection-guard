#!/usr/bin/env python3
"""Configure the installed Suricata/nDPI and the guard's dedicated NFQUEUE table."""
import argparse
import copy
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import yaml

import guard
import tun_network

MARK = 1481785689  # 0x58524159, XRAY
QUEUE = 0
SID = 9100001
TABLE = "xray_guard_inspect"
OWNER = "xray-connection-guard inspection"
QUEUE_UNIT = "xray-connection-guard-queue.service"
RULE = ('drop ip any any -> any any (msg:"nDPI BitTorrent blocked"; '
        f'ndpi-protocol:BitTorrent; sid:{SID}; rev:1;)\n')


class Paths:
    def __init__(self, root=Path("/")):
        self.config = root / "etc/xray-connection-guard"
        self.yaml = self.config / "suricata.yaml"
        self.rules = self.config / "bittorrent.rules"
        self.state = self.config / "inspection.json"
        self.units = root / "etc/systemd/system"
        self.helper = root / "opt/xray-connection-guard/inspector.py"
        self.log = root / "var/log/xray-ndpi"
        self.network = root / "run/xray-connection-guard/tun-network.json"


def run(args, *, data=None, check=True):
    result = subprocess.run(args, input=data, text=True, capture_output=True,
                            timeout=120, check=False)
    if check and result.returncode:
        raise RuntimeError(f"{shlex.join(map(str, args))}: "
                           f"{result.stderr.strip() or result.stdout.strip()}")
    return result


def existing_start():
    result = run(["systemctl", "show", "xray-ndpi.service", "-p", "ExecStart", "--value"],
                 check=False)
    return result.stdout if result.returncode == 0 else ""


def supported(binary):
    info = run([str(binary), "--build-info"], check=False)
    version = re.search(r"Suricata (?:version )?(\d+)\.", info.stdout)
    return bool(info.returncode == 0 and version and int(version.group(1)) >= 8 and
                re.search(r"NFQ(?:ueue)? support:\s+yes", info.stdout, re.I))


def discover(paths):
    start = existing_start()
    old_binary = re.search(r"\bpath=([^ ;}]+)", start)
    candidates = [os.environ.get("SURICATA_BIN")]
    previous = {}
    if paths.state.is_file():
        previous = json.loads(paths.state.read_text(encoding="utf-8"))
        candidates.append(previous.get("binary"))
    if old_binary:
        candidates.append(old_binary.group(1))
    candidates.extend([shutil.which("suricata"), "/usr/local/bin/suricata",
                       "/usr/bin/suricata", "/usr/sbin/suricata"])
    binary = None
    for candidate in dict.fromkeys(filter(None, candidates)):
        if not Path(candidate).is_file() or not os.access(candidate, os.X_OK):
            continue
        if supported(candidate):
            binary = str(Path(candidate).resolve())
            break
    if binary is None:
        raise RuntimeError("Suricata 8+ with NFQUEUE support was not found")

    old_yaml = re.search(r"(?:^|\s)(?:-c|--config)\s+([^ ;}]+)", start)
    bases = [os.environ.get("SURICATA_CONFIG")]
    if previous:
        if previous.get("base") != str(paths.yaml):
            bases.append(previous.get("base"))
    if old_yaml:
        bases.append(old_yaml.group(1))
    bases.extend([str(paths.yaml), "/etc/xray-ndpi/suricata.yaml",
                  "/etc/suricata/suricata.yaml", "/usr/local/etc/suricata/suricata.yaml"])
    base = next((Path(p) for p in bases if p and Path(p).is_file()), None)
    if base is None:
        raise RuntimeError("Cannot find the installed suricata.yaml. Set SURICATA_CONFIG.")
    config = yaml.safe_load(base.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise RuntimeError(f"Invalid Suricata configuration: {base}")
    plugins = config.get("plugins", []) or []
    if not isinstance(plugins, list) or any(not isinstance(p, str) for p in plugins):
        raise RuntimeError("Suricata plugins must be a list of paths")
    plugin = os.environ.get("NDPI_PLUGIN")
    if plugin:
        if not Path(plugin).is_file():
            raise RuntimeError(f"nDPI plugin not found: {plugin}")
    else:
        plugin = next((p for p in plugins if "ndpi" in p.lower() and Path(p).is_file()), None)
        if not plugin:
            for pattern in ("/usr/lib*/suricata/ndpi.so", "/usr/lib/*/suricata/ndpi.so",
                            "/usr/local/lib*/suricata/ndpi.so", "/opt/*/lib*/suricata/ndpi.so"):
                found = list(Path("/").glob(pattern.lstrip("/")))
                if found:
                    plugin = str(found[0])
                    break
    if plugin and plugin not in plugins:
        plugins.append(plugin)
    config["plugins"] = plugins
    return binary, base, config


def configuration(base, paths, eve):
    config = copy.deepcopy(base)
    config.pop("run-as", None)
    config["default-log-dir"] = str(eve.parent)
    config["default-rule-path"] = str(paths.config)
    config["rule-files"] = [str(paths.rules)]
    config["outputs"] = [{"eve-log": {
        "enabled": True, "filetype": "regular", "filename": str(eve),
        "threaded": False, "types": ["alert"]}}]
    config["nfq"] = {"mode": "accept", "fail-open": False}
    config.setdefault("stream", {})["inline"] = True
    config["unix-command"] = {"enabled": False}
    config["stats"] = {"enabled": False}
    config["logging"] = {"default-log-level": "notice", "outputs": [
        {"console": {"enabled": True}}]}
    return config


def dump_config(config):
    # Suricata requires the YAML 1.1 directive and document-start marker.
    return yaml.safe_dump(config, sort_keys=False, version=(1, 1), explicit_start=True)


def atomic_write(path, content, mode):
    encoded = content if isinstance(content, bytes) else content.encode("utf-8")
    if path.is_file() and path.read_bytes() == encoded:
        path.chmod(mode)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = path.with_name(path.name + f".bak.{time.time_ns()}")
        shutil.copy2(path, backup)
        print(f"[inspection] Backup: {backup}")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as file:
            temporary = Path(file.name)
            file.write(encoded)
        temporary.chmod(mode)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def unit_path(path):
    # systemd quoting is different from shell quoting; escape percent specifiers too.
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def inspector_unit(binary, paths):
    return f"""[Unit]
Description=BitTorrent inspection for Xray Connection Guard
Wants=network-online.target
Requires={QUEUE_UNIT}
After=network-online.target {QUEUE_UNIT}

[Service]
Type=simple
User=root
ExecStartPre=/usr/bin/python3 -B {unit_path(paths.helper)} check
ExecStart={unit_path(binary)} -c {unit_path(paths.yaml)} -q {QUEUE}
ExecStartPost=/usr/bin/python3 -B {unit_path(paths.helper)} ready
TimeoutStartSec=150
Restart=on-failure
RestartSec=3
UMask=0077

[Install]
WantedBy=multi-user.target
"""


def queue_unit(paths, interface=None):
    if interface:
        return f"""[Unit]
Description=Xray NFQUEUE and automatic IPv4 TUN routing
Before=xray-ndpi.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 -B {unit_path(paths.helper)} queue-watch
ExecStartPost=/usr/bin/python3 -B {unit_path(paths.helper)} network-ready
ExecReload=/usr/bin/python3 -B {unit_path(paths.helper)} queue
ExecStopPost=/usr/bin/python3 -B {unit_path(paths.helper)} queue-off
Restart=on-failure
RestartSec=3
TimeoutStartSec=90
RuntimeDirectory=xray-connection-guard
RuntimeDirectoryMode=0700
UMask=0077

[Install]
WantedBy=multi-user.target
"""
    return f"""[Unit]
Description=Xray traffic to Suricata NFQUEUE
Before=xray-ndpi.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 -B {unit_path(paths.helper)} queue
ExecReload=/usr/bin/python3 -B {unit_path(paths.helper)} queue
ExecStop=/usr/bin/python3 -B {unit_path(paths.helper)} queue-off
UMask=0077

[Install]
WantedBy=multi-user.target
"""


def preflight(binary, original):
    """Verify that the engine can actually load the nDPI BitTorrent rule."""
    with tempfile.TemporaryDirectory(prefix="xray-inspection-check-") as folder:
        staging = Paths(Path(folder))
        staging.config.mkdir(parents=True)
        staged = configuration(original, staging, Path(folder) / "eve.json")
        staging.rules.write_text(RULE, encoding="utf-8")
        staging.yaml.write_text(dump_config(staged), encoding="utf-8")
        run([binary, "-T", "-c", str(staging.yaml), "-l", folder])


def prepare(paths, guard_config, engine=None):
    cfg = json.loads(Path(guard_config).read_text(encoding="utf-8"))
    interface = guard.inspection_interface(cfg)
    source = cfg.get("eve", {})
    if source.get("type", "file") != "file":
        raise RuntimeError("Automatic local inspection requires eve.type=file")
    eve = Path(source.get("path", ""))
    if not eve.is_absolute() or not eve.name:
        raise RuntimeError("eve.path must be an absolute path to eve.json")
    if SID not in cfg.get("signatures", [SID]):
        raise RuntimeError(f"Add the managed BitTorrent SID {SID} to signatures")
    binary, base, original = engine if engine is not None else discover(paths)
    config = configuration(original, paths, eve)
    # Test in a staging directory before replacing any installed inspector files.
    preflight(binary, config)
    paths.config.mkdir(parents=True, exist_ok=True, mode=0o700)
    eve.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    state = {"binary": binary, "base": str(base), "queue": QUEUE}
    state.update({"interface": interface} if interface else {"mark": MARK})
    atomic_write(paths.rules, RULE, 0o600)
    atomic_write(paths.yaml, dump_config(config), 0o600)
    atomic_write(paths.state, json.dumps(state, indent=2) + "\n", 0o600)
    atomic_write(paths.units / "xray-ndpi.service", inspector_unit(binary, paths), 0o644)
    atomic_write(paths.units / QUEUE_UNIT, queue_unit(paths, interface), 0o644)
    selector = f"interface={interface}" if interface else f"mark={MARK}"
    print(f"[inspection] Configured Suricata/nDPI, SID={SID}, {selector}, queue={QUEUE}")


def selected_interface(paths):
    if not paths.state.is_file():
        return None
    state = json.loads(paths.state.read_text(encoding="utf-8"))
    return guard.inspection_interface({"inspection": state})


def check_interface(interface):
    if interface is None:
        return
    addresses = json.loads(run(["ip", "-j", "address", "show", "dev", interface]).stdout)
    if (len(addresses) != 1 or "UP" not in addresses[0].get("flags", []) or
            not any(address.get("scope") == "global" and address.get("family") in ("inet", "inet6")
                    for address in addresses[0].get("addr_info", []))):
        raise RuntimeError(f"Inspection interface {interface} must be UP with an assigned global-scope IP")


def check(paths):
    state = json.loads(paths.state.read_text(encoding="utf-8"))
    check_interface(selected_interface(paths))
    run([state["binary"], "-T", "-c", str(paths.yaml)])


def wait_ready():
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            rows = Path("/proc/net/netfilter/nfnetlink_queue").read_text().splitlines()
        except FileNotFoundError:
            rows = []
        if any(row.split() and int(row.split()[0]) == QUEUE for row in rows):
            return
        time.sleep(0.2)
    raise RuntimeError(f"Suricata did not open NFQUEUE {QUEUE}")


def queue_rules(interface=None):
    if interface is not None:
        guard.inspection_interface({"inspection": {"interface": interface}})
        return f"""table inet {TABLE} {{
    comment "{OWNER}"
    chain output {{
        type filter hook output priority 10; policy accept;
        meta l4proto {{ tcp, udp }} oifname "{interface}" counter queue num {QUEUE}
    }}
    chain input {{
        type filter hook input priority 10; policy accept;
        meta l4proto {{ tcp, udp }} iifname "{interface}" counter queue num {QUEUE}
    }}
}}
"""
    return f"""table inet {TABLE} {{
    comment "{OWNER}"
    chain output {{
        type filter hook output priority 10; policy accept;
        meta l4proto {{ tcp, udp }} meta mark {MARK} ct mark set {MARK}
        meta l4proto {{ tcp, udp }} ct mark {MARK} counter queue num {QUEUE}
    }}
    chain input {{
        type filter hook input priority 10; policy accept;
        meta l4proto {{ tcp, udp }} ct mark {MARK} counter queue num {QUEUE}
    }}
}}
"""


def update_queue(remove=False, paths=None, check_device=True):
    interface = None if remove else selected_interface(paths or Paths())
    if not remove and check_device:
        check_interface(interface)
    result = run(["nft", "list", "table", "inet", TABLE], check=False)
    prefix = ""
    if result.returncode == 0:
        # nft 1.0.2 preserves table comments but omits them from JSON output.
        ownership = rf'\Atable inet {TABLE}\s*\{{\s*comment "{re.escape(OWNER)}"(?:\s|;)'
        if not re.search(ownership, result.stdout):
            raise RuntimeError(f"Refusing to change an unowned nftables table {TABLE}")
        prefix = f"delete table inet {TABLE}\n"
    if remove:
        if prefix:
            run(["nft", "-f", "-"], data=prefix)
        return
    batch = prefix + queue_rules(interface)
    run(["nft", "-c", "-f", "-"], data=batch)
    run(["nft", "-f", "-"], data=batch)


def watch_network(paths):
    network = tun_network.Network(paths.network)
    last_error = None
    while True:
        try:
            interface = selected_interface(paths)
            if interface:
                network.ensure(interface)
            last_error = None
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            if str(exc) != last_error:
                print(f"[inspection] Waiting for IPv4 TUN: {exc}", flush=True)
                last_error = str(exc)
        time.sleep(1)


def wait_network(paths):
    interface = selected_interface(paths)
    if not interface:
        raise RuntimeError("No inspection interface configured")
    network = tun_network.Network(paths.network)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if network.ready(interface):
            return
        time.sleep(0.2)
    raise RuntimeError(f"IPv4 TUN routing for {interface} is not ready; check {QUEUE_UNIT} logs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "check", "ready", "queue", "queue-off",
                                          "queue-watch", "network-ready"))
    parser.add_argument("--config", default="/etc/xray-connection-guard/config.json")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run as root")
    paths = Paths()
    try:
        if args.action == "install":
            prepare(paths, args.config)
        elif args.action == "check":
            check(paths)
        elif args.action == "ready":
            wait_ready()
        elif args.action == "queue-watch":
            update_queue(paths=paths, check_device=False)
            watch_network(paths)
        elif args.action == "network-ready":
            wait_network(paths)
        elif args.action == "queue-off":
            tun_network.Network(paths.network).clear()
            update_queue(remove=True, paths=paths)
        else:
            update_queue(paths=paths)
            interface = selected_interface(paths)
            if interface:
                tun_network.Network(paths.network).ensure(interface)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, yaml.YAMLError) as exc:
        raise SystemExit(f"[inspection] {exc}") from exc


if __name__ == "__main__":
    main()
