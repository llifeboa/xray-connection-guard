#!/usr/bin/env python3
"""Run in private mount/network namespaces; see tests/README.md for commands.

Uses real installer/nftables and fake systemd/Suricata. Never starts host services.
"""
import json
import os
import shutil
import subprocess
import tempfile
from contextlib import ExitStack
from pathlib import Path

import yaml

import inspector


def run(args, *, env=None, check=True):
    result = subprocess.run(args, env=env, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result


def main():
    for namespace in ("net", "mnt"):
        if os.readlink(f"/proc/self/ns/{namespace}") == os.readlink(f"/proc/1/ns/{namespace}"):
            raise SystemExit("Refusing host access: unshare --mount --net is required")
    for tool in ("nft", "ss", "python3", "mount", "bash"):
        if not shutil.which(tool):
            raise SystemExit(f"Missing test dependency: {tool}")
    root = Path(__file__).resolve().parents[2]
    run(["mount", "--make-rprivate", "/"])
    # All installer destinations are hidden by private tmpfs mounts before mkdir/write.
    for destination in ("/etc", "/opt", "/var/log"):
        run(["mount", "-t", "tmpfs", "tmpfs", destination])
    Path("/etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    Path("/etc/group").write_text("root:x:0:\n")
    with tempfile.TemporaryDirectory(prefix="guard-installer-") as folder, ExitStack() as cleanup:
        work = Path(folder)
        commands = work / "bin"
        commands.mkdir()
        log = work / "systemctl.log"
        binary = commands / "suricata"
        binary.write_text("""#!/usr/bin/python3
import os, sys
from pathlib import Path
import yaml
if '--build-info' in sys.argv:
    print('This is Suricata version 8.0.2 RELEASE\\nNFQueue support: yes')
elif '-T' in sys.argv:
    if os.environ.get('INSPECTOR_TEST_REJECT'):
        raise SystemExit('test: unknown ndpi-protocol')
    text = Path(sys.argv[sys.argv.index('-c') + 1]).read_text()
    assert text.startswith('%YAML 1.1\\n---\\n')
    cfg = yaml.safe_load(text)
    for path in cfg['rule-files']:
        assert 'ndpi-protocol:BitTorrent;' in Path(path).read_text()
else:
    raise SystemExit('Test must not run a live inspector')
""")
        controller = commands / "systemctl"
        controller.write_text("""#!/usr/bin/python3
import os, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ['INSTALLER_TEST_LOG']).open('a') as log:
    log.write(' '.join(args) + '\\n')
if args[0] == 'show':
    binary = os.environ['SURICATA_BIN']
    print('{ path=' + binary + ' ; argv[]=' + binary + ' -c /etc/xray-ndpi/suricata.yaml -q 0 ; }')
elif args[0] == 'list-unit-files':
    print('xray-p2p-guard.service enabled')
elif args[:2] == ['reload-or-restart', 'xray-connection-guard-queue.service']:
    subprocess.run(['/usr/bin/python3', '-B', '/opt/xray-connection-guard/inspector.py', 'queue'], check=True)
""")
        forbidden = commands / "apt-get"
        forbidden.write_text("#!/bin/sh\necho 'Package installation is forbidden in this test' >&2\nexit 99\n")
        for executable in (binary, controller, forbidden):
            executable.chmod(0o755)
        base = Path("/etc/xray-ndpi/suricata.yaml")
        base.parent.mkdir(parents=True)
        base.write_text(yaml.safe_dump({"stream": {"memcap": "64mb"}}))
        original_base = base.read_bytes()
        unit_dir = Path("/etc/systemd/system")
        unit_dir.mkdir(parents=True)
        (unit_dir / "xray-ndpi.service").write_text("old inspector unit\n")
        env = dict(os.environ, PATH=str(commands) + ":" + os.environ["PATH"],
                   SURICATA_BIN=str(binary), INSTALLER_TEST_LOG=str(log),
                   PYTHONDONTWRITEBYTECODE="1")
        # A renamed Python ELF exercises real /proc discovery and open file descriptors.
        core_binary = commands / "xray"
        shutil.copyfile("/proc/self/exe", core_binary)
        core_binary.chmod(0o755)
        core_code = ("import signal, sys; "
                     "log = open(sys.argv[1], 'a'); "
                     "log.write('2025/01/15 18:00:00.000001 from tcp:203.0.113.20:50000 "
                     "accepted udp:198.51.100.1:6881 [IN >> DIRECT] email: test\\n'); "
                     "log.close(); print('ready', flush=True); signal.pause()")
        Path("/var/log/xray").mkdir()
        core = cleanup.enter_context(subprocess.Popen(
            [str(core_binary), "-u", "-c", core_code, "/var/log/xray/access.log"],
            env=dict(env, TZ="Etc/GMT-3"), stdout=subprocess.PIPE, text=True))
        cleanup.callback(core.terminate)
        assert core.stdout.readline().strip() == "ready"
        command = ["bash", str(root / "manage.sh")]
        run(command + ["install"], env=env)
        cfg_path = Path("/etc/xray-connection-guard/config.json")
        cfg = json.loads(cfg_path.read_text())
        cfg["firewall"]["tcp_ports"] = [8443]
        cfg["firewall"]["udp_ports"] = [8443]
        cfg["server_ips"] = ["192.0.2.10"]
        cfg["firewall"]["ban_seconds"] = 60
        cfg["access"] = {"type": "docker", "container": "remnanode", "path": "/var/log/xray/current"}
        cfg_path.write_text(json.dumps(cfg))
        run(command + ["install"], env=env)
        cfg = json.loads(cfg_path.read_text())
        assert "tcp_ports" not in cfg["firewall"]
        assert "udp_ports" not in cfg["firewall"]
        assert "server_ips" not in cfg
        assert cfg["firewall"]["ban_seconds"] == 600
        assert cfg["access"] == {"type": "file", "path": "/var/log/xray/access.log"}
        assert cfg["xray_timezone_name"] == "Etc/GMT-3"
        assert Path(cfg["xray_timezone"]).is_file()
        assert base.read_bytes() == original_base
        for name in ("xray-ndpi.service", "xray-connection-guard-queue.service", "xray-connection-guard.service"):
            assert (unit_dir / name).is_file()
        if shutil.which("systemd-analyze"):
            run(["systemd-analyze", "verify", str(unit_dir / "xray-ndpi.service"),
                 str(unit_dir / inspector.QUEUE_UNIT), str(unit_dir / "xray-connection-guard.service")])
        run(command + ["enable"], env=env)
        run(command + ["enable"], env=env)
        result = run(["nft", "-j", "list", "table", "inet", inspector.TABLE])
        rules = [entry["rule"] for entry in json.loads(result.stdout)["nftables"] if "rule" in entry]
        assert len(rules) == 3, 'Repeated enable must not duplicate inspection rules'
        mode = (unit_dir / "xray-connection-guard.service.d/mode.conf").read_text()
        assert '--mode enforce --allow-ban' in mode
        previous = {str(path): path.read_bytes() for path in (
            unit_dir / "xray-ndpi.service", unit_dir / inspector.QUEUE_UNIT,
            Path("/etc/xray-connection-guard/suricata.yaml"))}
        rejected = run(command + ["install"], env=dict(env, INSPECTOR_TEST_REJECT="1"), check=False)
        assert rejected.returncode != 0
        for path, content in previous.items():
            assert Path(path).read_bytes() == content, 'Failed preflight replaced working files'
        run(command + ["off"], env=env)
        run(["nft", "list", "table", "inet", inspector.TABLE])
        calls = log.read_text()
        assert 'restart xray-ndpi.service' in calls
        assert 'restart xray-connection-guard' in calls
        assert calls.index('disable --now xray-p2p-guard.service') < calls.index('reload-or-restart xray-connection-guard-queue.service')
        print('PASS: install/enable/off; real Xray process discovery with an idle log and automatic timezone; '
              'automatic files and service dependencies; config preserved; '
              'real nft rules installed without duplicates; failed preflight preserves inspector. '
              'Suricata and systemd were simulated.')


if __name__ == "__main__":
    main()
