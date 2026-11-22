#!/usr/bin/env python3
"""Real build test in a private mount namespace; see tests/README.md for commands.

Package writes use private overlays; the test never starts host services.
Internet access is needed to download build dependencies. No firewall changes are made.
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

import yaml

import inspector
from test_suricata_capture import check as check_capture


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    if os.readlink("/proc/self/ns/mnt") == os.readlink("/proc/1/ns/mnt"):
        raise SystemExit("Refusing host writes: unshare --mount is required")
    root = Path(__file__).resolve().parents[2]
    run(["mount", "--make-rprivate", "/"])
    with tempfile.TemporaryDirectory(prefix="xray-build-test-") as temporary:
        work = Path(temporary)
        print(f"Build test artifacts: {work}", flush=True)
        destinations = {str(Path(p).resolve()) for p in (
            "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/var/lib", "/var/cache", "/var/tmp")}
        for number, destination in enumerate(sorted(destinations)):
            upper, mount_work = work / f"upper{number}", work / f"work{number}"
            upper.mkdir()
            mount_work.mkdir()
            run(["mount", "-t", "overlay", "overlay", "-o",
                 f"lowerdir={destination},upperdir={upper},workdir={mount_work}", destination])
        for destination in ("/opt", "/var/log", "/root", "/run"):
            run(["mount", "-t", "tmpfs", "tmpfs", destination])
        # Keep the build log readable from outside this namespace while the build runs.
        logs = work / "logs"
        logs.mkdir()
        Path("/var/log/xray-connection-guard").mkdir()
        run(["mount", "--bind", str(logs), "/var/log/xray-connection-guard"])
        Path("/usr/sbin/policy-rc.d").write_text("#!/bin/sh\nexit 101\n")
        Path("/usr/sbin/policy-rc.d").chmod(0o755)
        commands = work / "commands"
        commands.mkdir()
        controller = commands / "systemctl"
        controller.write_text("#!/bin/sh\nexit 0\n")
        controller.chmod(0o755)
        env = {key: value for key, value in os.environ.items() if not key.lower().endswith("_proxy")}
        env.update(PATH=str(commands) + ":" + env["PATH"], PYTHONDONTWRITEBYTECODE="1")
        for key in ("SURICATA_BIN", "SURICATA_CONFIG", "NDPI_PLUGIN"):
            env.pop(key, None)
        run(["bash", str(root / "manage.sh"), "install"], env=env)
        paths = inspector.Paths()
        state = json.loads(paths.state.read_text())
        binary = state["binary"]
        assert binary.startswith("/opt/xray-connection-guard/engines/")
        config = yaml.safe_load(paths.yaml.read_text())
        assert Path(config["plugins"][0]).is_file()
        run([binary, "--build-info"])
        assert inspector.supported(binary)
        run(["python3", "-B", str(paths.helper), "check"], env=env)
        check_capture(binary, config)
        original_state = paths.state.read_bytes()
        engines = sorted(Path(binary).parents[2].iterdir())
        original_log = (logs / "install-suricata.log").read_bytes()
        forbidden = commands / "apt-get"
        forbidden.write_text("#!/bin/sh\necho 'Repeated install must reuse the engine' >&2\nexit 99\n")
        forbidden.chmod(0o755)
        run(["bash", str(root / "manage.sh"), "install"], env=env)
        assert paths.state.read_bytes() == original_state
        assert sorted(Path(binary).parents[2].iterdir()) == engines
        assert (logs / "install-suricata.log").read_bytes() == original_log
        print("PASS: real Suricata/nDPI build, NFQUEUE support, BitTorrent rule and repeated install", flush=True)


if __name__ == "__main__":
    main()
