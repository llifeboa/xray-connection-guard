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
    for destination in ("/etc", "/opt", "/var/log", "/run"):
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
    if 'LoadState' in args:
        if os.environ.get('INSTALLER_TEST_FAIL_QUERY'):
            raise SystemExit('test: cannot query systemd')
        print('loaded' if Path('/etc/systemd/system', args[1]).is_file() else 'not-found')
    else:
        binary = os.environ['SURICATA_BIN']
        print('{ path=' + binary + ' ; argv[]=' + binary + ' -c /etc/xray-ndpi/suricata.yaml -q 0 ; }')
elif args[0] == 'list-unit-files':
    print('xray-p2p-guard.service enabled')
elif args[0] == 'disable' and 'xray-ndpi.service' in args and os.environ.get('INSTALLER_TEST_FAIL_DISABLE'):
    raise SystemExit('test: service shutdown failed')
elif args[0] == 'disable' and args[-1] in ('xray-connection-guard', 'xray-connection-guard.service') and os.environ.get('INSTALLER_TEST_FAIL_OFF'):
    raise SystemExit('test: guard shutdown failed')
elif args[0] == 'disable' and args[-1] == 'xray-connection-guard-queue.service' and os.environ.get('INSTALLER_TEST_FAIL_QUEUE_STOP'):
    raise SystemExit('test: queue shutdown failed')
elif args[:2] == ['restart', 'xray-connection-guard-queue.service']:
    subprocess.run(['/usr/bin/python3', '-B', '/opt/xray-connection-guard/inspector.py', 'queue-off'], check=True)
    subprocess.run(['/usr/bin/python3', '-B', '/opt/xray-connection-guard/inspector.py', 'queue'], check=True)
""")
        forbidden = commands / "apt-get"
        forbidden.write_text("#!/bin/sh\necho 'Package installation is forbidden in this test' >&2\nexit 99\n")
        nft = commands / "nft"
        nft.write_text("#!/usr/bin/python3\nimport os, sys\n"
                       "if sys.argv[1:] in (['list', 'tables'], ['-j', 'list', 'tables']) and os.environ.get('INSTALLER_TEST_FAIL_NFT_LIST'):\n"
                       "    raise SystemExit('test: cannot list nftables')\n"
                       f"os.execv({shutil.which('nft')!r}, [{shutil.which('nft')!r}, *sys.argv[1:]])\n")
        for executable in (binary, controller, forbidden, nft):
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
        cleanup.callback(os.chdir, Path.cwd())
        os.chdir(work)
        (work / "version").write_text("import os\nprint('Xray ' + "
                                    "os.environ.get('INSTALLER_TEST_XRAY_VERSION', '26.11.9'))\n")
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
        for version in ("26.3.27", "unknown"):
            rejected = run(command + ["install"], env=dict(env, INSTALLER_TEST_XRAY_VERSION=version), check=False)
            assert rejected.returncode != 0
            assert "[guard] Installed." not in rejected.stdout
            assert not Path("/opt/xray-connection-guard").exists()
            assert not Path("/etc/xray-connection-guard").exists()
        direct = run(command + ["install", "--inspection-mark"],
                     env=dict(env, INSTALLER_TEST_XRAY_VERSION="26.3.27"))
        assert "DIRECT/SO_MARK only" in direct.stdout
        run(command + ["install"], env=env)
        assert Path("/opt/xray-connection-guard/log_maintenance.py").is_file()
        assert Path("/opt/xray-connection-guard/tun_network.py").is_file()
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
        run(["ip", "tuntap", "add", "dev", "xray-guard", "mode", "tun"])
        run(["ip", "address", "add", "198.18.0.1/30", "dev", "xray-guard"])
        run(["ip", "link", "set", "xray-guard", "up"])
        rp_filter = Path("/proc/sys/net/ipv4/conf/xray-guard/rp_filter")
        original_rp_filter = rp_filter.read_text()
        run(command + ["enable", "--inspection-interface", "xray-guard"], env=env)
        if shutil.which("systemd-analyze"):
            run(["systemd-analyze", "verify", str(unit_dir / "xray-ndpi.service"),
                 str(unit_dir / inspector.QUEUE_UNIT), str(unit_dir / "xray-connection-guard.service")])
        run(command + ["enable"], env=env)
        assert json.loads(cfg_path.read_text())["inspection"] == {"interface": "xray-guard"}
        assert json.loads(Path("/etc/xray-connection-guard/inspection.json").read_text())["interface"] == "xray-guard"
        selected_rules = run(["nft", "list", "table", "inet", inspector.TABLE]).stdout
        assert 'oifname "xray-guard"' in selected_rules and 'iifname "xray-guard"' in selected_rules
        selected_table = json.loads(run(["nft", "-j", "list", "table", "inet", inspector.TABLE]).stdout)
        assert len([entry for entry in selected_table["nftables"] if "rule" in entry]) == 2, selected_rules
        assert "mark" not in selected_rules, selected_rules
        assert len(json.loads(run(["ip", "-4", "-j", "route", "show", "table", "14817"]).stdout)) == 1
        assert len([rule for rule in json.loads(run(["ip", "-4", "-j", "rule", "show"]).stdout)
                    if rule.get("priority") == 14817]) == 1
        assert rp_filter.read_text().strip() == "2"
        run(["nft", "add", "table", "inet", "guard_test_preserve"])
        run(["nft", "add", "table", "inet", "xray_client_ban"])
        routing_before_disable = inspector.tun_network.routes()
        rules_before_disable = inspector.tun_network.rules()
        network_state = Path("/run/xray-connection-guard/tun-network.json")
        state_before_disable = network_state.read_bytes()
        run(["nft", "add", "set", "inet", "xray_client_ban", "clients_v4", "{ type ipv4_addr; }"])
        run(["nft", "add", "element", "inet", "xray_client_ban", "clients_v4", "{ 203.0.113.20 }"])
        saved_config = cfg_path.read_bytes()
        rejected = run(command + ["enable"], env=dict(env, INSTALLER_TEST_XRAY_VERSION="26.3.27"), check=False)
        assert rejected.returncode != 0
        assert "too old for TUN" in rejected.stderr
        assert cfg_path.read_bytes() == saved_config
        run(["nft", "list", "table", "inet", inspector.TABLE])
        saved_bans = run(["nft", "list", "table", "inet", "xray_client_ban"]).stdout
        rejected = run(command + ["off"], env=dict(env, INSTALLER_TEST_FAIL_OFF="1"), check=False)
        assert rejected.returncode != 0
        assert "Failed to stop/disable guard" in rejected.stderr
        assert "[guard] IP bans off and cleared" not in rejected.stdout
        assert run(["nft", "list", "table", "inet", "xray_client_ban"]).stdout == saved_bans
        rejected = run(command + ["off"], env=dict(env, INSTALLER_TEST_FAIL_NFT_LIST="1"), check=False)
        assert rejected.returncode != 0
        assert "[guard] IP bans off and cleared" not in rejected.stdout
        assert run(["nft", "list", "table", "inet", "xray_client_ban"]).stdout == saved_bans
        run(command + ["off"], env=env)
        run(command + ["off"], env=env)
        assert run(["nft", "list", "table", "inet", "xray_client_ban"], check=False).returncode != 0
        run(["nft", "add", "table", "inet", "xray_client_ban"])
        rejected = run(command + ["disable"], env=dict(env, INSTALLER_TEST_FAIL_DISABLE="1"), check=False)
        assert rejected.returncode != 0
        assert "[guard] Disabled:" not in rejected.stdout
        assert run(["nft", "list", "table", "inet", inspector.TABLE], check=False).returncode != 0
        assert inspector.tun_network.routes() == routing_before_disable
        run(command + ["disable"], env=env)
        run(command + ["disable"], env=env)
        assert run(["nft", "list", "table", "inet", inspector.TABLE], check=False).returncode != 0
        assert run(["nft", "list", "table", "inet", "xray_client_ban"], check=False).returncode != 0
        assert inspector.tun_network.routes() == routing_before_disable
        assert inspector.tun_network.rules() == rules_before_disable
        assert network_state.read_bytes() == state_before_disable
        assert rp_filter.read_text().strip() == "2"
        assert Path("/etc/xray-connection-guard/routing-only").is_file()
        run(["python3", "-B", "/opt/xray-connection-guard/inspector.py", "queue"], env=env)
        assert run(["nft", "list", "table", "inet", inspector.TABLE], check=False).returncode != 0
        assert inspector.tun_network.routes() == routing_before_disable
        run(["nft", "list", "table", "inet", "guard_test_preserve"])
        assert cfg_path.read_bytes() == saved_config
        assert core.poll() is None
        run(command + ["enable"], env=env)
        assert not Path("/etc/xray-connection-guard/routing-only").exists()
        run(["nft", "list", "table", "inet", inspector.TABLE])
        assert inspector.tun_network.routes()
        run(command + ["enable", "--inspection-mark"], env=env)
        assert "inspection" not in json.loads(cfg_path.read_text())
        assert json.loads(Path("/etc/xray-connection-guard/inspection.json").read_text())["mark"] == inspector.MARK
        assert "ct mark" in run(["nft", "list", "table", "inet", inspector.TABLE]).stdout
        assert not inspector.tun_network.routes()
        assert rp_filter.read_text() == original_rp_filter
        previous = {str(path): path.read_bytes() for path in (
            unit_dir / "xray-ndpi.service", unit_dir / inspector.QUEUE_UNIT,
            Path("/etc/xray-connection-guard/suricata.yaml"), cfg_path,
            Path("/opt/xray-connection-guard/configure_guard.py"))}
        rejected = run(command + ["install"], env=dict(env, INSTALLER_TEST_XRAY_VERSION="26.3.27"), check=False)
        assert rejected.returncode != 0
        assert "too old for TUN" in rejected.stderr
        for path, content in previous.items():
            assert Path(path).read_bytes() == content, 'Failed version check replaced working files'
        rejected = run(command + ["install"], env=dict(env, INSPECTOR_TEST_REJECT="1"), check=False)
        assert rejected.returncode != 0
        for path, content in previous.items():
            assert Path(path).read_bytes() == content, 'Failed preflight replaced working files'
        run(command + ["off"], env=env)
        run(["nft", "list", "table", "inet", inspector.TABLE])
        run(command + ["disable"], env=env)
        run(command + ["disable"], env=env)
        assert run(["nft", "list", "table", "inet", inspector.TABLE], check=False).returncode != 0
        run(["nft", "list", "table", "inet", "guard_test_preserve"])
        calls = log.read_text()
        assert 'disable --now xray-connection-guard' in calls
        assert 'disable --now xray-ndpi.service' in calls
        assert 'enable --now xray-connection-guard-queue.service' in calls
        assert 'disable --now xray-connection-guard xray-ndpi.service xray-connection-guard-queue.service' not in calls
        assert 'restart xray-ndpi.service' in calls
        assert 'restart xray-connection-guard' in calls
        assert calls.index('disable --now xray-p2p-guard.service') < calls.index('restart xray-connection-guard-queue.service')
        run(command + ["enable", "--inspection-interface", "xray-guard"], env=env)
        run(["nft", "add", "table", "inet", "xray_client_ban"])
        installed_files = list(Path('/opt/xray-connection-guard').glob('*.py'))
        installed_files.extend(unit_dir / name for name in (
            'xray-connection-guard.service', 'xray-ndpi.service', inspector.QUEUE_UNIT))
        saved_installed = {path: path.read_bytes() for path in installed_files}
        saved_routes = inspector.tun_network.routes()
        for failure in ('INSTALLER_TEST_FAIL_QUERY', 'INSTALLER_TEST_FAIL_OFF',
                        'INSTALLER_TEST_FAIL_DISABLE', 'INSTALLER_TEST_FAIL_QUEUE_STOP'):
            rejected = run(command + ['uninstall'], env=dict(env, **{failure: '1'}), check=False)
            assert rejected.returncode != 0
            assert '[guard] Uninstalled:' not in rejected.stdout
            assert inspector.tun_network.routes() == saved_routes
            for path, content in saved_installed.items():
                assert path.read_bytes() == content
        rejected = run(command + ['uninstall'], env=dict(env, INSTALLER_TEST_FAIL_NFT_LIST='1'), check=False)
        assert rejected.returncode != 0
        assert '[guard] Uninstalled:' not in rejected.stdout
        for path, content in saved_installed.items():
            assert path.read_bytes() == content
        run(command + ['enable'], env=env)
        retained = [cfg_path, base, binary,
                    Path('/opt/xray-connection-guard/engines/test/bin/suricata'),
                    Path('/var/log/xray-connection-guard/audit.jsonl'),
                    Path('/var/log/xray-ndpi/eve.json')]
        for path in retained[-3:]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('preserved test data\n')
        retained.extend(Path('/opt/xray-connection-guard').glob('*.bak.*'))
        retained.extend(unit_dir.glob('*.bak.*'))
        saved_retained = {path: path.read_bytes() for path in retained}
        result = run(command + ['uninstall'], env=env)
        assert '[guard] Uninstalled:' in result.stdout
        assert not inspector.tun_network.routes()
        assert not any(rule.get('priority') == 14817 for rule in inspector.tun_network.rules())
        assert rp_filter.read_text() == original_rp_filter
        assert not network_state.exists()
        assert not Path('/etc/xray-connection-guard/routing-only').exists()
        for path in installed_files:
            assert not path.exists(), path
        assert not (unit_dir / 'xray-connection-guard.service.d/mode.conf').exists()
        for table in (inspector.TABLE, 'xray_client_ban'):
            assert run(['nft', 'list', 'table', 'inet', table], check=False).returncode != 0
        run(['nft', 'list', 'table', 'inet', 'guard_test_preserve'])
        for path, content in saved_retained.items():
            assert path.read_bytes() == content
        assert core.poll() is None
        run(command + ['uninstall'], env=env)
        run(command + ['install'], env=env)
        run(command + ['enable'], env=env)
        assert inspector.tun_network.routes()
        run(['nft', 'list', 'table', 'inet', inspector.TABLE])
        run(command + ['disable'], env=env)
        assert Path('/etc/xray-connection-guard/routing-only').exists()
        run(command + ['uninstall'], env=env)
        assert not inspector.tun_network.routes()
        assert not Path('/etc/xray-connection-guard/routing-only').exists()
        assert rp_filter.read_text() == original_rp_filter
        print('PASS: install/enable/off/disable/uninstall; repeated disable clears bans/DPI while preserving TUN routes/state/rp_filter; '
              'queue reload stays routing-only, enable restores DPI; unrelated nftables and Xray preserved; shutdown failure reported; '
              'uninstall removes owned network/program/unit files in active and routing-only modes, preserves config/logs/engines/backups; '
              'repeated uninstall/reinstall works; '
              'uninstall systemd/nftables failures prevent false success and file removal; '
              'off failures preserve bans without false success; early core-version checks reject old/unknown TUN cores; '
              'old cores remain allowed with explicit DIRECT/SO_MARK; '
              'real Xray process discovery with an idle log and automatic timezone; '
              'automatic files and service dependencies; config preserved; '
              'real nft rules installed without duplicates; failed preflight preserves inspector. '
              'Suricata and systemd were simulated.')


if __name__ == "__main__":
    main()
