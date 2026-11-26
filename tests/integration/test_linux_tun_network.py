#!/usr/bin/env python3
"""Check automatic IPv4 TUN routing in a private Linux network namespace."""
import json
import os
import subprocess
import tempfile
from pathlib import Path

import tun_network as network


INTERFACE = "xray-guard"
SOURCE = "198.18.0.1"


def run(arguments):
    return subprocess.run(arguments, check=True, text=True, capture_output=True).stdout


def device():
    run(["ip", "tuntap", "add", "dev", INTERFACE, "mode", "tun"])
    run(["ip", "link", "set", INTERFACE, "up"])
    run(["ip", "address", "add", SOURCE + "/30", "dev", INTERFACE])
    (network.RP_FILTER_ROOT / INTERFACE / "rp_filter").write_text("1\n")


def rejected(manager, pattern):
    try:
        manager.ensure(INTERFACE)
    except RuntimeError as exc:
        assert pattern in str(exc), str(exc)
    else:
        raise AssertionError("Conflicting routing configuration was accepted")


def main():
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise SystemExit("Refusing host access: unshare --net is required")
    run(["ip", "link", "set", "lo", "up"])
    run(["ip", "link", "add", "physical", "type", "dummy"])
    run(["ip", "link", "set", "physical", "up"])
    run(["ip", "address", "add", "192.0.2.1/24", "dev", "physical"])
    run(["ip", "route", "add", "default", "via", "192.0.2.2", "dev", "physical"])
    device()
    original_main = run(["ip", "-4", "-j", "route", "show", "table", "main"])
    original_ipv6 = run(["ip", "-6", "-j", "rule", "show"])
    rp_filter = network.RP_FILTER_ROOT / INTERFACE / "rp_filter"
    with tempfile.TemporaryDirectory(prefix="guard-tun-network-") as folder:
        manager = network.Network(Path(folder) / "state.json")
        run(["ip", "-4", "rule", "add", "priority", str(network.PRIORITY), "fwmark", "7",
             "lookup", "12345"])
        rejected(manager, "another rule")
        assert not manager.state.exists() and rp_filter.read_text().strip() == "1"
        assert not network.routes()
        run(["ip", "-4", "rule", "del", "priority", str(network.PRIORITY), "fwmark", "7",
             "lookup", "12345"])
        run(["ip", "-4", "route", "add", "198.51.100.0/24", "dev", "physical", "table", str(network.TABLE)])
        occupied = network.routes()
        rejected(manager, "another route")
        assert network.routes() == occupied and not manager.state.exists()
        run(["ip", "-4", "route", "del", "198.51.100.0/24", "dev", "physical", "table", str(network.TABLE)])
        manager.ensure(INTERFACE)
        manager.ensure(INTERFACE)
        assert manager.ready(INTERFACE)
        selected = [rule for rule in network.rules() if rule.get("priority") == network.PRIORITY]
        assert len(selected) == 1 and network.owned(selected[0]), selected
        assert len(network.routes()) == 1 and network.owned(network.routes()[0])
        assert rp_filter.read_text().strip() == "2"
        route = json.loads(run(["ip", "-4", "-j", "route", "get", "198.51.100.20", "oif", INTERFACE]))[0]
        assert route["dev"] == INTERFACE and route["prefsrc"] == SOURCE, route
        assert run(["ip", "-4", "-j", "route", "show", "table", "main"]) == original_main
        assert run(["ip", "-6", "-j", "rule", "show"]) == original_ipv6
        run(["ip", "link", "delete", INTERFACE])
        device()
        manager.ensure(INTERFACE)
        assert manager.ready(INTERFACE)
        run(["ip", "-4", "address", "del", SOURCE + "/30", "dev", INTERFACE])
        run(["ip", "-4", "address", "add", "198.18.0.5/30", "dev", INTERFACE])
        manager.ensure(INTERFACE)
        assert manager.ready(INTERFACE) and network.routes()[0]["prefsrc"] == "198.18.0.5"
        manager.clear()
        manager.clear()
        assert not network.routes()
        assert not any(rule.get("priority") == network.PRIORITY for rule in network.rules())
        assert rp_filter.read_text().strip() == "1"
        manager.ensure(INTERFACE)
        run(["ip", "link", "delete", INTERFACE])
        manager.clear()
        assert not any(rule.get("priority") == network.PRIORITY for rule in network.rules()), network.rules()
        device()
        run(["ip", "-4", "route", "add", "default", "dev", INTERFACE, "src", SOURCE, "table", str(network.TABLE)])
        run(["ip", "-4", "rule", "add", "priority", str(network.PRIORITY), "oif", INTERFACE,
             "lookup", str(network.TABLE)])
        borrowed_routes, borrowed_rules = network.routes(), network.rules()
        manager.ensure(INTERFACE)
        assert manager.ready(INTERFACE)
        manager.clear()
        assert network.routes() == borrowed_routes and network.rules() == borrowed_rules
        assert rp_filter.read_text().strip() == "1"
        try:
            manager.ensure("physical")
        except RuntimeError as exc:
            assert "non-TUN" in str(exc), str(exc)
        else:
            raise AssertionError("Physical interface was accepted")
    print("PASS: automatic IPv4 TUN routing, idempotency, interface recreation and cleanup; "
          "foreign rules/routes and physical default preserved; borrowed routes preserved; IPv6 untouched")


if __name__ == "__main__":
    main()
