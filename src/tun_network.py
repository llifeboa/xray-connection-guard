#!/usr/bin/env python3
"""Maintain IPv4 policy routing for the guard's native TUN interface."""
import contextlib
import ipaddress
import json
import subprocess
import tempfile
from pathlib import Path


TABLE = 14817
PRIORITY = 14817
PROTOCOL = 242
OWNER = "xray-connection-guard"
RP_FILTER_ROOT = Path("/proc/sys/net/ipv4/conf")


def run(arguments, check=True):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=15)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(map(str, arguments))}: {result.stderr.strip()}")
    return result


def routes():
    result = run(["ip", "-4", "-N", "-j", "route", "show", "table", str(TABLE)], check=False)
    if result.returncode:
        if "FIB table does not exist" in result.stderr:
            return []
        raise RuntimeError(result.stderr.strip())
    return json.loads(result.stdout or "[]")


def rules():
    return json.loads(run(["ip", "-4", "-N", "-j", "rule", "show"]).stdout)


def matching_rule(rule, interface):
    return (rule.get("priority") == PRIORITY and str(rule.get("table")) == str(TABLE) and
            rule.get("oif") == interface and rule.get("src", "all") == "all" and
            set(rule) <= {"priority", "table", "oif", "src", "protocol", "oif_detached"})


def matching_route(route, interface, source):
    return (route.get("dst") == "default" and route.get("dev") == interface and
            route.get("prefsrc") == source and not set(route.get("flags", [])) - {"linkdown"} and
            set(route) <= {"dst", "dev", "prefsrc", "protocol", "scope", "flags"})


def owned(entry):
    return str(entry.get("protocol")) == str(PROTOCOL)


class Network:
    def __init__(self, state):
        self.state = Path(state)

    @contextlib.contextmanager
    def locked(self):
        import fcntl
        self.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.state.with_suffix(".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def saved(self):
        if not self.state.exists():
            return None
        saved = json.loads(self.state.read_text(encoding="utf-8"))
        if saved.get("owner") != OWNER:
            raise RuntimeError(f"Refusing to change unowned network state: {self.state}")
        return saved

    def save(self, state):
        data = json.dumps(state, sort_keys=True) + "\n"
        if self.state.is_file() and self.state.read_text(encoding="utf-8") == data:
            return
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.state.parent,
                                         delete=False) as output:
            temporary = Path(output.name)
            try:
                output.write(data)
                output.close()
                temporary.chmod(0o600)
                temporary.replace(self.state)
            finally:
                temporary.unlink(missing_ok=True)

    def plan(self, interface):
        devices = json.loads(run(["ip", "-j", "-d", "address", "show", "dev", interface]).stdout)
        if len(devices) != 1 or "UP" not in devices[0].get("flags", []):
            raise RuntimeError(f"TUN interface {interface} must be UP")
        device = devices[0]
        link = device.get("linkinfo", {})
        if link.get("info_kind") != "tun" or link.get("info_data", {}).get("type") != "tun":
            raise RuntimeError(f"Refusing to configure a non-TUN interface: {interface}")
        source = next((address["local"] for address in device.get("addr_info", [])
                       if address.get("family") == "inet" and address.get("scope") == "global"), None)
        if source is None or not isinstance(ipaddress.ip_address(source), ipaddress.IPv4Address):
            raise RuntimeError(f"Set an IPv4 gateway in Xray's TUN settings for {interface}")
        selected_rules = [rule for rule in rules() if rule.get("priority") == PRIORITY or
                          str(rule.get("table")) == str(TABLE)]
        selected_routes = routes()
        previous = self.saved()
        if len(selected_rules) > 1 or any(not matching_rule(rule, interface) for rule in selected_rules):
            raise RuntimeError(f"Policy rule priority/table {PRIORITY} is already used by another rule")
        if len(selected_routes) > 1 or any(
                not matching_route(route, interface, source) and not (
                    previous and previous["interface"] == interface and previous.get("route_owned") and
                    owned(route) and matching_route(route, interface, previous["source"]))
                for route in selected_routes):
            raise RuntimeError(f"Routing table {TABLE} is already used by another route: {selected_routes}")
        return device, source, selected_routes, selected_rules

    def ensure(self, interface):
        with self.locked():
            device, source, selected_routes, selected_rules = self.plan(interface)
            previous = self.saved()
            if previous and previous["interface"] != interface:
                self._clear()
                previous = None
            rp_filter = RP_FILTER_ROOT / interface / "rp_filter"
            original = rp_filter.read_text().strip()
            if previous and previous["ifindex"] == device["ifindex"]:
                original = previous["rp_filter"]
            self.save({"owner": OWNER, "interface": interface, "ifindex": device["ifindex"],
                       "source": source, "rp_filter": original,
                       "route_owned": not selected_routes or bool(previous and previous.get("route_owned") and
                                                                  owned(selected_routes[0])),
                       "rule_owned": not selected_rules or bool(previous and previous.get("rule_owned") and
                                                                owned(selected_rules[0]))})
            changed = False
            if not selected_routes or not matching_route(selected_routes[0], interface, source):
                operation = "replace" if selected_routes else "add"
                run(["ip", "-4", "route", operation, "default", "dev", interface, "src", source,
                     "proto", str(PROTOCOL), "table", str(TABLE)])
                changed = True
            if not selected_rules:
                run(["ip", "-4", "rule", "add", "priority", str(PRIORITY), "oif", interface,
                     "lookup", str(TABLE), "protocol", str(PROTOCOL)])
                changed = True
            if rp_filter.read_text().strip() != "2":
                rp_filter.write_text("2\n")
                changed = True
            if changed:
                print(f"[inspection] IPv4 TUN configured: interface={interface}, source={source}, "
                      f"table={TABLE}, priority={PRIORITY}, rp_filter=2", flush=True)

    def ready(self, interface):
        try:
            device, source, selected_routes, selected_rules = self.plan(interface)
            saved = self.saved()
            return bool(saved and saved["interface"] == interface and
                        saved["ifindex"] == device["ifindex"] and selected_rules and
                        selected_routes and matching_route(selected_routes[0], interface, source) and
                        (RP_FILTER_ROOT / interface / "rp_filter").read_text().strip() == "2")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            return False

    def clear(self):
        with self.locked():
            self._clear()

    def _clear(self):
        saved = self.saved()
        if not saved:
            return
        interface = saved["interface"]
        for rule in rules():
            if saved.get("rule_owned") and owned(rule) and matching_rule(rule, interface):
                run(["ip", "-4", "rule", "del", "priority", str(PRIORITY), "oif", interface,
                     "lookup", str(TABLE), "protocol", str(PROTOCOL)])
        for route in routes():
            if (saved.get("route_owned") and owned(route) and
                    route.get("dev") == interface and route.get("dst") == "default"):
                run(["ip", "-4", "route", "del", "default", "dev", interface,
                     "proto", str(PROTOCOL), "table", str(TABLE)])
        result = run(["ip", "-j", "link", "show", "dev", interface], check=False)
        devices = json.loads(result.stdout or "[]")
        if not result.returncode and devices and devices[0]["ifindex"] == saved["ifindex"]:
            rp_filter = RP_FILTER_ROOT / interface / "rp_filter"
            if rp_filter.read_text().strip() == "2":
                rp_filter.write_text(saved["rp_filter"] + "\n")
        self.state.unlink()
