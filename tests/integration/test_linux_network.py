#!/usr/bin/env python3
"""Run in a private network namespace; see tests/README.md for commands."""
import json
import os
from unittest import mock

import guard as g


def main():
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise SystemExit("Refusing host firewall access: unshare --net is required")
    old, new, client = "192.0.2.10", "192.0.2.11", "203.0.113.20"
    g.run(["ip", "link", "set", "lo", "up"])
    g.run(["ip", "address", "add", old + "/32", "dev", "lo"])
    addresses = set()
    monitor = g.AddressMonitor(addresses)
    with mock.patch.object(g.time, "monotonic", return_value=100):
        monitor.refresh(initial=True)
    assert addresses == {old}
    # Upgrade an existing table with a port-limited rule, keeping its timed sets.
    legacy = g.firewall_rules().replace(
        "ip saddr @clients_v4 counter drop", "ip saddr @clients_v4 tcp dport 443 counter drop")
    g.run(["nft", "-f", "-"], stdin=legacy)
    fw = g.Firewall({"allowlist_cidrs": []}, addresses)
    # Documentation-only client in an isolated namespace; no production exception.
    fw.allowed_to_ban = lambda ip: ip == client
    fw.ensure()
    fw.ban(client)

    def banned_element():
        entries = json.loads(g.run(["nft", "-j", "list", "set", "inet", g.TABLE, "clients_v4"]).stdout)
        clients = next(entry["set"] for entry in entries["nftables"] if "set" in entry)
        return clients["elem"][0]["elem"]

    before = banned_element()
    g.run(["ip", "address", "del", old + "/32", "dev", "lo"])
    g.run(["ip", "address", "add", new + "/32", "dev", "lo"])
    g.run(["ip", "-6", "address", "add", "2001:db8::1/128", "dev", "lo", "nodad"])
    with mock.patch.object(g.time, "monotonic", return_value=699):
        assert not monitor.refresh()
    assert addresses == {old}
    with mock.patch.object(g.time, "monotonic", return_value=700), mock.patch.object(g, "LOG") as log:
        assert monitor.refresh()
        assert log.info.call_args.args[0].startswith("Node addresses changed")
    assert fw.server_ips is addresses
    assert addresses == {new, "2001:db8::1"}
    event = {"event_type": "alert", "timestamp": "2025-01-15T10:00:00Z",
             "alert": {"action": "blocked", "signature_id": 9100001},
             "src_ip": new, "dest_ip": "198.51.100.1", "src_port": 50000, "dest_port": 6881,
             "proto": "UDP", "flow_id": 123}
    assert g.get_peer_alert(event, addresses, {9100001})["peer"] == ("198.51.100.1", 6881)
    event["src_ip"] = old
    assert g.get_peer_alert(event, addresses, {9100001}) is None
    after = banned_element()
    assert before["val"] == after["val"] == client
    assert 590 < after["expires"] <= before["expires"] <= 600
    fw.ensure()
    assert banned_element()["val"] == client
    rules = json.loads(g.run(["nft", "-j", "list", "table", "inet", g.TABLE]).stdout)
    text = json.dumps([entry["rule"] for entry in rules["nftables"] if "rule" in entry])
    assert '"dport"' not in text and '"sport"' not in text
    print("PASS: real IPv4/IPv6 address change at the 600s check; shared addresses updated; "
          "active ban preserved; legacy port restrictions removed without clearing timed sets")


if __name__ == "__main__":
    main()
