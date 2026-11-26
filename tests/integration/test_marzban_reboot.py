#!/usr/bin/env python3
"""Check automatic startup after restarting the disposable systemd Docker host."""
import argparse
import contextlib
import json
import os
from pathlib import Path

import test_marzban_host as host


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path("/results/test-state.json"))
    parser.add_argument("--output", type=Path, default=Path("/results/reboot"))
    args = parser.parse_args()
    if not os.environ.get("XRAY_GUARD_ISOLATED_HOST") or Path("/proc/1/comm").read_text().strip() != "systemd":
        parser.error("Only run in the disposable Docker host")
    args.output.mkdir(parents=True, exist_ok=True)
    state = json.loads(args.state.read_text())
    report = {"tests": [], "manual_enable": False}
    try:
        with contextlib.ExitStack() as cleanup:
            exit_worker, client_worker = host.network_setup(cleanup, args.output, state)
            panel = host.Panel()
            host.wait(panel.login, "automatic Marzban startup", timeout=90)
            host.wait(host.live_units, "automatic guard/Suricata/queue startup", timeout=90)
            ports = host.client_setup(cleanup, client_worker.pid, args.output, state)
            host.ordinary_traffic(client_worker.pid, ports)
            monitor = host.ManagementMonitor(client_worker.pid)
            monitor.start()
            cleanup.callback(monitor.stop)
            report["core"] = panel.request("/core")
            report["network"] = host.snapshot()
            report["units"] = host.command(["systemctl", "is-active", *host.UNITS]).stdout.split()
            report["tests"].append("Cold start: real systemd, nested Docker, Marzban, guard, Suricata and IPv4 TUN recover without enable")
            print("PASS: " + report["tests"][-1], flush=True)
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        report["journal"] = host.command(["journalctl", "-u", "docker.service", "-u", host.UNITS[0],
            "-u", host.UNITS[1], "-u", host.UNITS[2], "--no-pager"], check=False).stdout
        (args.output / "result.json").write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
