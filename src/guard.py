#!/usr/bin/env python3
"""Suricata EVE -> Xray access -> timed ingress IP bans.

Python standard library only. No firewall modifications in monitor mode.
Access records omit the egress port; freedom INFO records provide it for XUDP.
Joining these records is probabilistic, not proof of individual user identity.
"""
import argparse
import collections
import datetime as dt
import ipaddress
import json
import logging
import math
import os
import queue
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from zoneinfo import ZoneInfo

import log_maintenance

LOG = logging.getLogger("xray-connection-guard")
UTC = dt.timezone.utc
ACCESS_RE = re.compile(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+from\s+(\S+)\s+accepted\s+(tcp|udp):([^\s]+)\s+\[[^\]]+\]\s+email:\s*(\S+)')
UDP_OPEN_RE = re.compile(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\[Info\]\s+\[(\d+)\]\s+proxy/freedom: connection opened to udp:(\S+), local endpoint (\S+), remote endpoint (\S+)')
XUDP_RE = re.compile(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\[Info\]\s+\[(\d+)\]\s+common/mux: XUDP (new|hit) \[([\d ]+)\]')


def load_timezone(value):
    if not isinstance(value, str) or not value:
        raise ValueError("xray_timezone must be a timezone name or an absolute TZif path")
    if value.startswith("/"):
        with open(value, "rb") as file:
            return ZoneInfo.from_file(file, key=value)
    return ZoneInfo(value)


def timestamp(value):
    if isinstance(value, dt.datetime):
        parsed = value
    elif isinstance(value, str):
        # Suricata writes +0000; Python 3.10 requires the +00:00 form.
        value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value)
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("Timestamp missing")
    if parsed.tzinfo is None:
        raise ValueError("Timezone missing")
    return parsed.astimezone(UTC).timestamp()


def parse_addr_port(value):
    try:
        if value.startswith("["):
            host, port = value[1:].split("]:", 1)
        else:
            host, port = value.rsplit(":", 1)
        return str(ipaddress.ip_address(host)), int(port)
    except (ValueError, TypeError):
        return None


def parse_access(line, tz):
    m = ACCESS_RE.search(line.strip())
    if not m:
        return None
    source = m.group(2)
    if source.startswith(("tcp:", "udp:")):
        source = source.split(":", 1)[1]
    client = parse_addr_port(source)
    remote = parse_addr_port(m.group(4))
    if not remote:
        return None  # domain-only log entry cannot be safely correlated
    parsed = dt.datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S.%f")
    ts = parsed.replace(tzinfo=tz).astimezone(UTC).timestamp()
    return {"ts": ts, "proto": m.group(3).upper(), "peer": remote,
            "email": m.group(5),
            "client_ip": client[0] if client else None,
            "client_port": client[1] if client else None}


def get_peer_alert(e, server_ips, signatures, stats=None):
    def ignored(reason):
        if stats is not None:
            stats["eve_ignored_" + reason] += 1
        return None

    if not isinstance(e, dict):
        return ignored("invalid_event")
    if e.get("event_type") != "alert":
        return ignored("non_alert")
    alert = e.get("alert") or {}
    if not isinstance(alert, dict):
        return ignored("invalid_event")
    if alert.get("action") != "blocked":
        return ignored("not_blocked")
    try:
        sid = int(alert.get("signature_id", 0))
    except (ValueError, TypeError):
        return ignored("signature")
    if sid not in signatures:
        return ignored("signature")
    proto = str(e.get("proto", "")).upper()
    if proto not in ("TCP", "UDP"):
        return ignored("protocol")
    try:
        src_ip = str(ipaddress.ip_address(e["src_ip"]))
        dst_ip = str(ipaddress.ip_address(e["dest_ip"]))
        src_port = int(e["src_port"])
        dst_port = int(e["dest_port"])
        ts = timestamp(e["timestamp"])
    except (ValueError, KeyError, TypeError):
        return ignored("invalid_event")
    if src_ip in server_ips and dst_ip not in server_ips:
        peer = (dst_ip, dst_port)
        local = (src_ip, src_port)
    elif dst_ip in server_ips and src_ip not in server_ips:
        peer = (src_ip, src_port)
        local = (dst_ip, dst_port)
    else:
        return ignored("server_ip")
    # Flow id groups repeated alerts on the same connection.
    flow_id = e.get("flow_id")
    if flow_id is None:
        return ignored("flow_id")
    flow_start = ts
    flow = e.get("flow")
    if isinstance(flow, dict) and flow.get("start") is not None:
        try:
            started = timestamp(flow["start"])
            if started > ts:
                raise ValueError("Flow starts after its alert")
            flow_start = started
        except (ValueError, TypeError):
            if stats is not None:
                stats["eve_invalid_flow_start"] += 1
    return {"ts": ts, "flow_start_ts": flow_start, "proto": proto, "peer": peer, "local": local,
            "flow": str(flow_id), "sid": sid}


def parse_udp_table(text):
    """Decode Linux /proc/net/udp{,6}; addresses use native-endian 32-bit words."""
    sockets = collections.defaultdict(set)
    for line in text.splitlines()[1:]:
        fields = line.split()
        try:
            address, port = fields[1].split(":")
            packed = b"".join(int(address[i:i + 8], 16).to_bytes(4, sys.byteorder)
                              for i in range(0, len(address), 8))
            endpoint = (str(ipaddress.ip_address(packed)), int(port, 16))
            inode = int(fields[9])
        except (ValueError, IndexError, OverflowError):
            continue
        if inode:
            sockets[endpoint].add(inode)
    return sockets


def read_udp_sockets():
    sockets = parse_udp_table(Path("/proc/self/net/udp").read_text(encoding="ascii"))
    try:
        ipv6 = Path("/proc/self/net/udp6").read_text(encoding="ascii")
    except FileNotFoundError:  # IPv6 can be disabled in the kernel.
        return sockets
    for endpoint, inodes in parse_udp_table(ipv6).items():
        sockets[endpoint].update(inodes)
    return sockets


class UdpBindings:
    """Keep an initial access -> freedom socket join while that socket is alive.

    A single XUDP socket can send to peers never mentioned in access records.
    Inodes prevent attributing a recycled port to the previous client. Unknown
    or shared sockets and XUDP handoffs deliberately do not provide an owner.
    """
    def __init__(self, max_delay, stats):
        self.max_delay = max_delay
        self.stats = stats
        self.entries = {}
        self.by_peer = collections.defaultdict(set)
        self.sockets = {}
        self.xudp_sessions = {}
        self.handoffs = {}
        self.dirty = False
        self.last_scan = -math.inf
        self.last_warning = -math.inf

    def _remember(self, entry, record):
        if entry["ambiguous"] or not -3 <= entry["ts"] - record["ts"] <= self.max_delay:
            return
        key = (record["client_ip"], record["email"])
        entry["owners"][key] = record
        # Two different IPs already disqualify a join. Keep that evidence
        # without retaining every visitor to popular shared DNS peers.
        entry["ambiguous"] = (record["client_ip"] is None
                              or len({owner[0] for owner in entry["owners"]}) > 1)

    def add_access(self, record):
        if record["proto"] == "UDP":
            for local in self.by_peer.get(record["peer"], ()):
                self._remember(self.entries[local], record)

    def observe(self, line, tz, access):
        if "proxy/freedom: connection opened to udp:" in line:
            match = UDP_OPEN_RE.search(line.strip())
            if not match:
                return False
            destination = parse_addr_port(match[3])
            local = parse_addr_port(match[4])
            if not destination or not local or not 0 < local[1] <= 65535:
                return False
            parsed = dt.datetime.strptime(match[1], "%Y/%m/%d %H:%M:%S.%f")
            opened = parsed.replace(tzinfo=tz).timestamp()
            old = self.entries.get(local)
            if old is None or opened > old["ts"]:
                if old is not None:
                    self.by_peer[old["peer"]].discard(local)
                self.entries[local] = {"ts": opened, "session": match[2], "peer": destination,
                                       "inode": None, "checked": False, "valid": False,
                                       "dead": None, "owners": {}, "ambiguous": False}
                entry = self.entries[local]
                self.by_peer[destination].add(local)
                for record in access.get(("UDP", *destination), ()):
                    self._remember(entry, record)
                    if entry["ambiguous"]:
                        break
                self.dirty = True
            self.stats["udp_socket_logs"] += 1
            return True
        if "common/mux: XUDP " in line:
            match = XUDP_RE.search(line.strip())
            if match:
                parsed = dt.datetime.strptime(match[1], "%Y/%m/%d %H:%M:%S.%f")
                stamp = parsed.replace(tzinfo=tz).timestamp()
                global_id = " ".join(match[4].split())
                if match[3] == "new":
                    self.xudp_sessions[global_id] = (match[2], stamp)
                elif global_id in self.xudp_sessions:
                    # A hit reuses an old socket on another inbound connection.
                    # Its new source IP is not included in this INFO record.
                    session, _ = self.xudp_sessions[global_id]
                    self.handoffs[session] = max(stamp, self.handoffs.get(session, -math.inf))
                    self.dirty = True
                return True
        return False

    def refresh(self, force=False):
        now = time.monotonic()
        if not force and not self.dirty and now - self.last_scan < 5:
            return
        self.last_scan = now
        self.dirty = False
        active_sessions = {entry["session"] for entry in self.entries.values()}
        cutoff = time.time() - 600
        self.xudp_sessions = {key: value for key, value in self.xudp_sessions.items()
                              if value[0] in active_sessions or value[1] >= cutoff}
        self.handoffs = {key: value for key, value in self.handoffs.items()
                         if key in active_sessions or value >= cutoff}
        if not self.entries:
            self.stats["udp_socket_bindings"] = 0
            return
        try:
            sockets = read_udp_sockets()
        except OSError as exc:
            for entry in self.entries.values():
                entry["valid"] = False
            self.stats["udp_socket_bindings"] = 0
            self.stats["udp_socket_scan_errors"] += 1
            if now - self.last_warning >= 60:
                LOG.warning("Cannot verify UDP socket owners: %s", exc)
                self.last_warning = now
            return
        self.sockets = sockets
        for local, entry in list(self.entries.items()):
            inodes = sockets.get(local, set())
            if not entry["checked"]:
                fresh = -3 <= time.time() - entry["ts"] <= self.max_delay
                entry["inode"] = next(iter(inodes)) if len(inodes) == 1 and fresh else None
                entry["checked"] = True
            entry["valid"] = (entry["dead"] is None and entry["inode"] is not None
                              and inodes == {entry["inode"]}
                              and entry["ts"] > self.handoffs.get(entry["session"], -math.inf))
            if not entry["valid"]:
                if entry["dead"] is None:
                    entry["dead"] = now
                    self.by_peer[entry["peer"]].discard(local)
                if now - entry["dead"] > 600:
                    del self.entries[local]
                continue
        self.by_peer = collections.defaultdict(set, {peer: locals_ for peer, locals_ in self.by_peer.items()
                                                    if locals_})
        self.stats["udp_socket_bindings"] = sum(e["valid"] for e in self.entries.values())

    def matches(self, event):
        if event["proto"] != "UDP" or not event.get("local"):
            return None
        server_ip, port = event["local"]
        server = ipaddress.ip_address(server_ip)
        addresses = {server_ip, "::"} | ({"0.0.0.0"} if server.version == 4 else set())
        entries = [self.entries[(address, port)] for address in addresses
                   if (address, port) in self.entries]
        if not entries:
            return None  # Legacy access-only logs still support direct peer matching.
        started = event.get("flow_start_ts", event["ts"])
        inodes = set().union(*(self.sockets.get((address, port), set()) for address in addresses))
        if (len(inodes) != 1 or any(not entry["valid"] or started < entry["ts"]
                                   for entry in entries)):
            return [], "udp_socket_unverified"
        records = [record for entry in entries for record in entry["owners"].values()]
        return records, None if records else "udp_socket_owner_missing"


class FileFollower:
    """Tail regular file from end. Reopen on inode change or truncation."""
    def __init__(self, path, name, out):
        self.path = Path(path)
        self.name = name
        self.out = out
        self.fp = None
        self.inode = None
        self.buffer = ""
        self.lines = collections.deque()
        self.last_warning = 0

    def _drain(self):
        while self.lines:
            try:
                self.out.put_nowait((self.name, self.lines[0]))
            except queue.Full:
                return False
            self.lines.popleft()
        return True

    def _read(self):
        data = self.fp.read(4 * 1024 * 1024)
        if not data:
            return False
        self.buffer += data
        pieces = self.buffer.split("\n")
        self.buffer = pieces.pop()
        self.lines.extend(pieces)
        return True

    def step(self):
        if not self._drain():
            return
        try:
            stat = self.path.stat()
            rotated = self.fp is not None and self.inode != (stat.st_dev, stat.st_ino)
            truncated = self.fp is not None and stat.st_size < self.fp.tell()
            if rotated and self._read():
                # Finish the renamed file before switching to its replacement.
                self._drain()
                return
            if rotated or truncated:
                self.fp.close()
                self.fp = None
                self.buffer = ""
                LOG.info("%s log rotated/truncated", self.name)
            if self.fp is None:
                self.fp = self.path.open("r", encoding="utf-8", errors="replace")
                self.inode = (stat.st_dev, stat.st_ino)
                # Startup: ignore historical lines. On rotation: read new file from beginning.
                if not (rotated or truncated):
                    self.fp.seek(0, 2)
                LOG.info("Following %s: %s", self.name, self.path)
            self._read()
            self._drain()
        except OSError as ex:
            if time.time() - self.last_warning > 10:
                LOG.warning("Cannot read %s: %s", self.path, ex)
                self.last_warning = time.time()

    def close(self):
        if self.fp is not None:
            self.fp.close()
            self.fp = None


class CommandFollower:
    """Follow Docker-stored logs without requiring a container bind mount."""
    def __init__(self, args, name, out):
        self.args = args
        self.name = name
        self.out = out
        self.proc = None
        self.stopped = threading.Event()
        self.last_start = 0

    def step(self):
        if self.proc and self.proc.poll() is None:
            return
        if time.monotonic() - self.last_start < 5:
            return
        self.last_start = time.monotonic()
        try:
            self.proc = subprocess.Popen(self.args, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, text=True,
                                         bufsize=1, start_new_session=True)
            LOG.info("Following %s with %s", self.name, shlex.join(self.args))
            threading.Thread(target=self.reader, args=(self.proc,), daemon=True).start()
        except OSError as ex:
            LOG.error("Could not start %s follower: %s", self.name, ex)

    def reader(self, proc):
        try:
            for line in proc.stdout:
                warned = False
                while not self.stopped.is_set():
                    try:
                        self.out.put((self.name, line.rstrip("\n")), timeout=1)
                        break
                    except queue.Full:
                        if not warned:
                            LOG.warning("Log queue full: waiting to deliver %s events", self.name)
                            warned = True
                else:
                    return
        finally:
            proc.stdout.close()

    def close(self):
        self.stopped.set()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()


def validate_source(source, name):
    if not isinstance(source, dict):
        raise ValueError(f"{name} must be an object")
    kind = source.get("type", "file")
    if kind not in ("file", "docker"):
        raise ValueError(f"Unsupported {name} log source type {kind!r}")
    if not isinstance(source.get("path"), str) or not source["path"].strip():
        raise ValueError(f"{name}.path must be a non-empty string")
    if kind == "docker":
        container = source.get("container")
        if not isinstance(container, str) or not re.fullmatch(r"[a-zA-Z0-9][\w.-]*", container):
            raise ValueError(f"Invalid {name}.container")


def follower(source, name, out):
    validate_source(source, name)
    kind = source.get("type", "file")
    if kind == "file":
        return FileFollower(source["path"], name, out)
    if kind == "docker":
        container = source["container"]
        path = source["path"]
        # tail -F handles log rotation, but requires tail inside the container.
        return CommandFollower(["docker", "exec", container, "tail", "-n", "0", "-F", path], name, out)


def audit_append(path, event):
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(file, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        os.write(fd, (json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n").encode())
    finally:
        os.close(fd)



# Standalone extension: no panel APIs or account changes.
# This bans all traffic to/from the observed client IP, on every port.
TABLE = "xray_client_ban"
BAN_SECONDS = 600
BAN_RETRY_SECONDS = 5
NETWORK_REFRESH_SECONDS = 600


def run(argv, *, stdin=None, check=True):
    result = subprocess.run(argv, input=stdin, text=True, capture_output=True,
                            timeout=20, check=False)
    if check and result.returncode:
        raise RuntimeError(f"{shlex.join(argv)} failed ({result.returncode}): "
                           f"{result.stderr.strip() or result.stdout.strip()}")
    return result


def discover_server_ips():
    # NFQUEUE in OUTPUT sees local source addresses before POSTROUTING/SNAT.
    interfaces = json.loads(run(["ip", "-j", "address", "show", "scope", "global"]).stdout)
    if not isinstance(interfaces, list):
        raise ValueError("Unexpected ip address JSON")
    addresses = set()
    for interface in interfaces:
        if not isinstance(interface, dict) or not isinstance(interface.get("addr_info", []), list):
            raise ValueError("Unexpected ip address entry")
        for item in interface.get("addr_info", []):
            if not isinstance(item, dict):
                raise ValueError("Unexpected ip address entry")
            if item.get("family") not in ("inet", "inet6") or not item.get("local"):
                continue
            flags = {flag.lower() for flag in item.get("flags", [])}
            if flags & {"tentative", "dadfailed"} or item.get("tentative") or item.get("dadfailed"):
                continue
            address = ipaddress.ip_address(item["local"])
            if not (address.is_loopback or address.is_link_local or
                    address.is_unspecified or address.is_multicast):
                addresses.add(str(address))
    if not addresses:
        raise RuntimeError("No usable node IP addresses found")
    return addresses


class AddressMonitor:
    """Update the shared address set without restarting the guard or its firewall."""
    def __init__(self, server_ips):
        self.server_ips = server_ips
        self.next_check = 0

    def refresh(self, *, initial=False):
        now = time.monotonic()
        if not initial and now < self.next_check:
            return False
        self.next_check = now + NETWORK_REFRESH_SECONDS
        try:
            current = discover_server_ips()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            if initial:
                raise
            LOG.error("Node address check failed; keeping server_ips=%s; retry_in=%ds: %s",
                      sorted(self.server_ips), NETWORK_REFRESH_SECONDS, exc)
            return False
        previous = sorted(self.server_ips)
        changed = current != self.server_ips
        self.server_ips.clear()
        self.server_ips.update(current)
        if initial:
            LOG.info("Node addresses detected: server_ips=%s; refresh_seconds=%d",
                     sorted(current), NETWORK_REFRESH_SECONDS)
        elif changed:
            LOG.info("Node addresses changed: old=%s new=%s added=%s removed=%s",
                     previous, sorted(current), sorted(current - set(previous)),
                     sorted(set(previous) - current))
        else:
            LOG.info("Node address check: unchanged server_ips=%s; next_check_in=%ds",
                     sorted(current), NETWORK_REFRESH_SECONDS)
        return changed


class LogSizeMonitor:
    """Check Docker/Supervisor logs without pausing event processing."""
    def __init__(self, source):
        self.source = source
        self.next_check = 0
        self.worker = None
        self.pending_restart = False

    def refresh(self, *, initial=False):
        if self.source.get("type", "file") != "docker":
            return False
        if self.worker is not None and self.worker.is_alive():
            return False
        now = time.monotonic()
        if not initial and now < self.next_check:
            return False
        self.next_check = now + NETWORK_REFRESH_SECONDS
        self.worker = threading.Thread(target=self.check, daemon=True, name="xray-log-size")
        self.worker.start()
        return True

    def check(self):
        container = self.source["container"]
        try:
            # Supervisor already needs Python in its container. Stream only this
            # static helper; no environment variables, credentials, or log data.
            script = Path(log_maintenance.__file__).read_text(encoding="utf-8")
            command = ["docker", "exec", "-i", "--user", "0", container, "python3", "-",
                       log_maintenance.SUPERVISOR_CONFIG, self.source["path"]]
            response = run(command, stdin=script, check=False)
            try:
                result = json.loads(response.stdout)
            except (ValueError, TypeError):
                raise RuntimeError("Cannot run Supervisor log check inside the container") from None
            if not isinstance(result, dict) or result.get("status") not in (
                    "changed", "unchanged", "unsupported", "error"):
                raise RuntimeError("Unexpected Supervisor log check result")
            if response.returncode or result["status"] == "error":
                raise RuntimeError(result.get("error", "Supervisor log check failed"))
            if result["status"] == "unsupported":
                LOG.info("Xray log size check: container=%s skipped=%s; next_check_in=%ds",
                         container, result["reason"], NETWORK_REFRESH_SECONDS)
                return
            if result["status"] == "changed":
                self.pending_restart = True
                LOG.warning("Xray log limit increased: container=%s previous_bytes=%s minimum_bytes=%d; "
                            "restarting container to apply the change",
                            container, result["previous_limit_bytes"], log_maintenance.MIN_LOG_BYTES)
            if self.pending_restart:
                # No supervisorctl dependency: older node images omit its RPC configuration.
                run(["docker", "restart", "--timeout", "10", container])
                self.pending_restart = False
                LOG.info("Xray log size check: container=%s limit_bytes=%s container_restarted=true; "
                         "next_check_in=%ds", container, result["limit_bytes"], NETWORK_REFRESH_SECONDS)
            else:
                LOG.info("Xray log size check: container=%s limit_bytes=%s container_restarted=false; "
                         "next_check_in=%ds", container, result["limit_bytes"], NETWORK_REFRESH_SECONDS)
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
            LOG.error("Xray log size check failed: container=%s; retry_in=%ds: %s",
                      container, NETWORK_REFRESH_SECONDS, exc)

    def close(self):
        if self.worker is not None:
            self.worker.join(timeout=1)


def validate(cfg):
    if not isinstance(cfg, dict):
        raise ValueError("Config must be an object")
    for name in ("eve", "access", "firewall"):
        if name not in cfg:
            raise ValueError(f"Missing config field: {name}")
    # Legacy fields no longer control detection or limit bans to selected ports.
    cfg.pop("server_ips", None)
    load_timezone(cfg.get("xray_timezone", "UTC"))
    for name in ("eve", "access"):
        validate_source(cfg[name], name)
    signatures = cfg.get("signatures", [9100001])
    if (not isinstance(signatures, list) or not signatures
            or any(type(sid) is not int or not 1 <= sid <= 4294967295 for sid in signatures)):
        raise ValueError("signatures must be a non-empty list of positive 32-bit integers")
    buffer = cfg.get("correlation_buffer_seconds", 3)
    if (type(buffer) not in (int, float) or not math.isfinite(buffer) or buffer < 0):
        raise ValueError("correlation_buffer_seconds must be finite and non-negative")
    audit_path = cfg.get("audit_path", "/var/log/xray-connection-guard/audit.jsonl")
    if not isinstance(audit_path, str) or not audit_path.strip():
        raise ValueError("audit_path must be a non-empty string")
    fw = cfg["firewall"]
    if not isinstance(fw, dict):
        raise ValueError("firewall must be an object")
    fw.pop("tcp_ports", None)
    fw.pop("udp_ports", None)
    if fw.get("ban_seconds", BAN_SECONDS) != BAN_SECONDS:
        raise ValueError(f"This version requires ban_seconds={BAN_SECONDS} (10 minutes)")
    fw["allowlist_cidrs"] = [str(ipaddress.ip_network(x, strict=False))
                             for x in fw.get("allowlist_cidrs", [])]
    if fw.get("host_network", False) is not True:
        raise ValueError("Set firewall.host_network=true ONLY after verifying Xray uses host network")
    defaults = {"max_match_delay_seconds": 60, "window_seconds": 300,
                "min_distinct_peers": 5, "min_distinct_flows": 5}
    for name, default in defaults.items():
        value = cfg.get(name, default)
        if type(value) is not int or value <= 0:
            raise ValueError(f"{name} must be a positive integer")


def firewall_chain_rules(direction):
    addr = "saddr" if direction == "input" else "daddr"
    for family, st in (("ip", "clients_v4"), ("ip6", "clients_v6")):
        yield f"{family} {addr} @{st} counter drop"


def firewall_rules():
    """A dedicated nftables table, independent of Suricata and panel rules."""
    lines = [
        f"table inet {TABLE} {{",
        f"  set clients_v4 {{ type ipv4_addr; flags timeout; timeout {BAN_SECONDS}s; size 4096; }}",
        f"  set clients_v6 {{ type ipv6_addr; flags timeout; timeout {BAN_SECONDS}s; size 4096; }}",
    ]
    for direction in ("input", "output"):
        lines.append(f"  chain {direction} {{")
        lines.append(f"    type filter hook {direction} priority -10; policy accept;")
        lines.extend("    " + rule for rule in firewall_chain_rules(direction))
        lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


class Firewall:
    def __init__(self, config, server_ips):
        self.config = config
        self.server_ips = server_ips
        self.allow = [ipaddress.ip_network(x) for x in config["allowlist_cidrs"]]
        self.spec = firewall_rules()
        self.initialized = False

    def allowed_to_ban(self, ip):
        address = ipaddress.ip_address(ip)
        if not address.is_global or str(address) in self.server_ips:
            return False
        return not any(address in net for net in self.allow)

    def ensure(self):
        if not shutil.which("nft"):
            raise RuntimeError("nft command not found: apt install nftables")
        check = run(["nft", "list", "table", "inet", TABLE], check=False)
        if check.returncode == 0:
            existing = check.stdout
            if not ("clients_v4" in existing and "clients_v6" in existing
                    and "hook input" in existing and "hook output" in existing):
                raise RuntimeError(f"Existing nft table inet {TABLE} looks unexpected; inspect manually")
            # Refresh both owned chains in one batch; keep timed sets and their
            # existing elements so a restart does not lift active bans.
            lines = []
            for direction in ("input", "output"):
                lines.append(f"flush chain inet {TABLE} {direction}")
                lines.extend(f"add rule inet {TABLE} {direction} {rule}"
                             for rule in firewall_chain_rules(direction))
            spec = "\n".join(lines) + "\n"
            run(["nft", "-c", "-f", "-"], stdin=spec)
            run(["nft", "-f", "-"], stdin=spec)
            LOG.info("Updated nftables inet %s: all ports and protocols; existing bans preserved", TABLE)
        else:
            run(["nft", "-c", "-f", "-"], stdin=self.spec)
            run(["nft", "-f", "-"], stdin=self.spec)
            LOG.info("Created nftables table %s (all ports and protocols, input/output)", TABLE)
        self.initialized = True

    def ban(self, ip):
        if not self.allowed_to_ban(ip):
            raise ValueError(f"Client IP {ip} is protected, non-public or equals a server IP")
        if not self.initialized:
            self.ensure()
        ip_obj = ipaddress.ip_address(ip)
        set_name = "clients_v4" if ip_obj.version == 4 else "clients_v6"
        # The explicit timeout also works with sets created by older releases.
        element = f"{{ {ip} timeout {BAN_SECONDS}s }}"
        command = ["nft", "add", "element", "inet", TABLE, set_name, element]
        try:
            run(command)
        except (RuntimeError, OSError, subprocess.TimeoutExpired):
            # A firewall reload may have removed the dedicated table.
            self.initialized = False
            self.ensure()
            run(command)
        LOG.warning("BAN APPLIED client_ip=%s duration=%ds scope=all-ports-and-protocols",
                    ip, BAN_SECONDS)
        # Kill established TCP sockets in the host netns (not conntrack table entries).
        killed = []
        destination = f"[{ip}]" if ip_obj.version == 6 else ip
        # Include dual-stack sockets and every local port.
        cmd = ["ss", "-K", "-n", "-t", "state", "established", f"dst {destination}"]
        try:
            result = run(cmd)
            killed.append({"scope": "all", "ok": True, "output": result.stdout.strip()[:400]})
        except Exception as exc:
            LOG.error("Cannot force-close TCP sockets for %s: %s", ip, exc)
            killed.append({"scope": "all", "ok": False, "error": str(exc)})
        return killed


class Correlator:
    def __init__(self, cfg, server_ips, mode, firewall):
        self.cfg = cfg
        self.mode = mode
        self.server_ips = server_ips
        self.firewall = firewall
        self.max_delay = int(cfg.get("max_match_delay_seconds", 60))
        self.window = int(cfg.get("window_seconds", 300))
        self.min_peers = int(cfg.get("min_distinct_peers", 5))
        self.min_flows = int(cfg.get("min_distinct_flows", 5))
        self.signatures = {int(s) for s in cfg.get("signatures", [9100001])}
        self.tz = load_timezone(cfg.get("xray_timezone", "UTC"))
        self.access = collections.defaultdict(collections.deque)
        self.events = collections.defaultdict(collections.deque)
        self.seen_flows = {}
        self.cooldown = {}
        self.retry_bans = {}
        self.audit_path = cfg.get("audit_path", "/var/log/xray-connection-guard/audit.jsonl")
        self.pending = collections.deque()
        self.pending_flows = set()
        self.stats = collections.Counter(dict.fromkeys(
            ("access_lines", "access", "access_ignored", "eve_lines", "alerts",
             "matched", "matched_by_udp_socket", "udp_socket_logs", "udp_socket_bindings",
             "correlation_waits", "unmatched_expired", "bans", "ban_errors"), 0))
        self.udp = UdpBindings(self.max_delay, self.stats)
        self.last_summary = time.monotonic()

    def add_access(self, line):
        self.stats["access_lines"] += 1
        item = parse_access(line, self.tz)
        if item is None:
            if not self.udp.observe(line, self.tz, self.access):
                self.stats["access_ignored"] += 1
            return
        key = (item["proto"], *item["peer"])
        self.access[key].append(item)
        self.udp.add_access(item)
        self.stats["access"] += 1

    def add_eve(self, line):
        self.stats["eve_lines"] += 1
        try:
            item = get_peer_alert(json.loads(line), self.server_ips, self.signatures, self.stats)
        except json.JSONDecodeError:
            self.stats["eve_invalid_json"] += 1
            return
        if item:
            self.stats["alerts"] += 1
            fkey = (item["proto"], item["flow"], item["peer"])
            if fkey not in self.seen_flows and fkey not in self.pending_flows:
                self.pending.append((time.monotonic(), item))
                self.pending_flows.add(fkey)

    def process_pending(self):
        buffer = float(self.cfg.get("correlation_buffer_seconds", 3))
        now = time.monotonic()
        # One kernel snapshot for the whole event batch, including retries.
        self.udp.refresh(force=bool(self.pending))
        for _ in range(len(self.pending)):
            arrived, event = self.pending.popleft()
            age = now - arrived
            if age < buffer:
                self.pending.append((arrived, event))
                continue
            if not self.evaluate(event, refresh_udp=False):
                if age < buffer + self.max_delay:
                    # Access records can be delivered later than EVE records.
                    self.pending.append((arrived, event))
                    continue
                self._log_unmatched(event)
            self.pending_flows.discard((event["proto"], event["flow"], event["peer"]))
        if time.monotonic() - self.last_summary >= 60:
            LOG.info("stats %s", dict(self.stats))
            self.last_summary = time.monotonic()
        cutoff = time.time() - max(self.max_delay + self.window, 600)
        for k in list(self.access):
            while self.access[k] and self.access[k][0]["ts"] < cutoff:
                self.access[k].popleft()
            if not self.access[k]:
                del self.access[k]
        event_cutoff = time.time() - self.window
        for ip in list(self.events):
            active = collections.deque(e for e in self.events[ip] if e["ts"] >= event_cutoff)
            if active:
                self.events[ip] = active
            else:
                del self.events[ip]
        for ip, until in list(self.retry_bans.items()):
            if ip not in self.events:
                del self.retry_bans[ip]
            elif time.monotonic() >= until:
                self._maybe_ban(ip, self.events[ip])
        for flow, ts in list(self.seen_flows.items()):
            if ts < time.time() - 1800:
                del self.seen_flows[flow]
        for key, until in list(self.cooldown.items()):
            if time.monotonic() > until + 3600:
                del self.cooldown[key]

    def _access_matches(self, e):
        records = self.access.get((e["proto"], *e["peer"]), ())
        # Xray logs dispatch, while nDPI can classify a UDP flow much later.
        # Keep the alert timestamp for the five-minute incident window.
        started = e.get("flow_start_ts", e["ts"])
        matches = [a for a in records if -3 <= started - a["ts"] <= self.max_delay]
        return records, matches

    def _matches(self, e):
        socket_match = self.udp.matches(e)
        if socket_match is not None:
            records, reason = socket_match
            return records, records, reason, "udp_socket"
        records, matches = self._access_matches(e)
        return records, matches, None, "peer"

    def _log_unmatched(self, e):
        records, matches, reason, method = self._matches(e)
        ips = sorted({a["client_ip"] for a in matches if a["client_ip"]})
        if not reason:
            if not records:
                reason = "no_access_for_peer"
            elif not matches:
                reason = "time_window"
            elif any(not a["client_ip"] for a in matches):
                reason = "client_ip_missing"
            else:
                reason = "multiple_client_ips"
        started = e.get("flow_start_ts", e["ts"])
        nearest = (round(started - min(records, key=lambda a: abs(started - a["ts"]))["ts"], 3)
                   if records else None)
        self.stats["unmatched_expired"] += 1
        self.stats["unmatched_" + reason] += 1
        LOG.warning("BitTorrent flow unmatched: reason=%s flow_id=%s proto=%s peer=%s:%d "
                    "local=%s via=%s flow_start=%s detected=%s "
                    "nearest_access_delta_seconds=%s candidate_ips=%s",
                    reason, e["flow"], e["proto"], *e["peer"],
                    e.get("local"), method,
                    dt.datetime.fromtimestamp(started, UTC).isoformat(),
                    dt.datetime.fromtimestamp(e["ts"], UTC).isoformat(), nearest, ips)

    def evaluate(self, e, refresh_udp=True):
        fkey = (e["proto"], e["flow"], e["peer"])
        if fkey in self.seen_flows:
            return True
        if refresh_udp:
            self.udp.refresh(force=True)
        _, matches, reason, method = self._matches(e)
        ips = {a["client_ip"] for a in matches if a["client_ip"]}
        if reason or len(ips) != 1 or any(not a["client_ip"] for a in matches):
            if not e.get("_correlation_waited"):
                self.stats["correlation_waits"] += 1
                e["_correlation_waited"] = True
            return False
        self.seen_flows[fkey] = time.time()
        ip = next(iter(ips))
        e = dict(e, client_ip=ip, emails=tuple(sorted({a["email"] for a in matches})),
                 correlation=method)
        q = self.events[ip]
        q.append(e)
        while q and q[0]["ts"] < e["ts"] - self.window:
            q.popleft()
        self.stats["matched"] += 1
        if method == "udp_socket":
            self.stats["matched_by_udp_socket"] += 1
        LOG.info("BitTorrent match: client_ip=%s proto=%s peer=%s:%d flow_id=%s "
                 "via=%s local=%s peers=%d/%d flows=%d/%d",
                 ip, e["proto"], *e["peer"], e["flow"], method, e.get("local"),
                 len({item["peer"][0] for item in q}), self.min_peers,
                 len({item["flow"] for item in q}), self.min_flows)
        self._maybe_ban(ip, q)
        return True

    def _maybe_ban(self, ip, q):
        peers = {entry["peer"][0] for entry in q}
        flows = {entry["flow"] for entry in q}
        if len(peers) < self.min_peers or len(flows) < self.min_flows:
            self.retry_bans.pop(ip, None)
            return
        if not self.firewall.allowed_to_ban(ip):
            self.stats["protected_ip"] += 1
            LOG.warning("SKIP protected/nonpublic client_ip=%s", ip)
            q.clear()
            self.retry_bans.pop(ip, None)
            return
        if self.cooldown.get(ip, 0) > time.monotonic():
            return
        if self.retry_bans.get(ip, 0) > time.monotonic():
            return
        emails = sorted({email for entry in q for email in entry["emails"]})
        email = emails[0] if len(emails) == 1 else None
        record = {
            "time": dt.datetime.now(UTC).isoformat(), "email": email, "emails": emails,
            "client_ip": ip, "unique_peers": len(peers), "unique_flows": len(flows),
            "evidence": [{"peer_ip": x["peer"][0], "peer_port": x["peer"][1],
                          "proto": x["proto"], "flow_id": x["flow"],
                          "correlation": x.get("correlation", "peer"), "local": x.get("local")}
                         for x in list(q)[-10:]],
            "mode": self.mode, "ban_seconds": BAN_SECONDS, "result": "monitor-only"
        }
        record["ban_scope"] = "all-ports-and-protocols"
        LOG.warning("P2P INCIDENT emails=%s client_ip=%s peers=%d flows=%d",
                    emails, ip, len(peers), len(flows))
        successful = True
        if self.mode == "enforce":
            try:
                record["tcp_socket_actions"] = self.firewall.ban(ip)
                record["result"] = f"banned-{BAN_SECONDS}s"
                self.stats["bans"] += 1
            except Exception as exc:
                successful = False
                record["result"] = "ban-error: " + str(exc)
                self.stats["ban_errors"] += 1
                self.retry_bans[ip] = time.monotonic() + BAN_RETRY_SECONDS
                LOG.exception("BAN FAILED client_ip=%s", ip)
        if successful:
            # Only an actual ban (or a monitor report) consumes the evidence.
            q.clear()
            self.retry_bans.pop(ip, None)
            self.cooldown[ip] = time.monotonic() + BAN_SECONDS
        try:
            audit_append(self.audit_path, record)
        except OSError:
            LOG.exception("Cannot write audit log; enforcement continues client_ip=%s", ip)
        LOG.warning("INCIDENT RESULT=%s client_ip=%s email=%s", record["result"], ip, email)


def effective_settings(cfg, server_ips, mode):
    sources = {}
    for name in ("access", "eve"):
        source = cfg[name]
        sources[name] = {"type": source.get("type", "file"), "path": source["path"]}
        if source.get("type") == "docker":
            sources[name]["container"] = source["container"]
    settings = {
        "mode": mode, "server_ips": sorted(server_ips), "server_ips_detection": "automatic",
        "network_refresh_seconds": NETWORK_REFRESH_SECONDS, **sources,
        "log_size_check": {"enabled": cfg["access"].get("type") == "docker",
                           "interval_seconds": NETWORK_REFRESH_SECONDS,
                           "minimum_bytes": log_maintenance.MIN_LOG_BYTES,
                           "restart": "only after increasing the Supervisor log limit"},
        "xray_timezone": cfg.get("xray_timezone", "UTC"),
        "xray_timezone_name": cfg.get("xray_timezone_name", cfg.get("xray_timezone", "UTC")),
        "xray_utc_offset_seconds": int(dt.datetime.now(load_timezone(
            cfg.get("xray_timezone", "UTC"))).utcoffset().total_seconds()),
        "signatures": cfg.get("signatures", [9100001]),
        "audit_path": cfg.get("audit_path", "/var/log/xray-connection-guard/audit.jsonl"),
        "correlation_buffer_seconds": cfg.get("correlation_buffer_seconds", 3),
        "correlation_time_source": "flow.start; fallback=alert.timestamp",
        "udp_socket_tracking": "freedom INFO local endpoint; live kernel inode; initial access owner",
        "firewall": {"host_network": cfg["firewall"]["host_network"], "table": TABLE,
                     "scope": "all-ports-and-protocols", "directions": ["input", "output"],
                     "ban_seconds": BAN_SECONDS, "retry_seconds": BAN_RETRY_SECONDS,
                     "allowlist_cidrs": cfg["firewall"]["allowlist_cidrs"]},
    }
    for name, default in (("max_match_delay_seconds", 60), ("window_seconds", 300),
                          ("min_distinct_peers", 5), ("min_distinct_flows", 5)):
        settings[name] = cfg.get(name, default)
    return settings


def main():
    parser = argparse.ArgumentParser(description="Standalone Xray P2P connection guard (no panel APIs)")
    parser.add_argument("--config", required=True)
    parser.add_argument("--mode", choices=("monitor", "enforce"), default="monitor")
    parser.add_argument("--allow-ban", action="store_true", help="Explicitly permit nftables bans and ss -K")
    parser.add_argument("--check", action="store_true", help="Validate config and exit without modifying firewall")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    with open(args.config, encoding="utf-8") as file:
        cfg = json.load(file)
    validate(cfg)
    if args.mode == "enforce" and not args.allow_ban:
        parser.error("enforce requires --allow-ban")
    if args.check:
        print("OK: configuration valid; server_ips=automatic network_refresh=%ds "
              "scope=all-ports-and-protocols ban=%ds" % (NETWORK_REFRESH_SECONDS, BAN_SECONDS))
        return
    server_ips = set()
    network = AddressMonitor(server_ips)
    try:
        network.refresh(initial=True)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"[guard] Cannot detect node addresses: {exc}\n")
    firewall = Firewall(cfg["firewall"], server_ips)
    LOG.info("Startup settings: %s", json.dumps(effective_settings(cfg, server_ips, args.mode),
                                             ensure_ascii=False, sort_keys=True))
    if args.mode == "enforce":
        if os.geteuid() != 0:
            parser.error("enforce must run as root")
        if not shutil.which("ss"):
            parser.error("ss missing: apt install iproute2")
        firewall.ensure()
    out = queue.Queue(maxsize=50000)
    followers = [follower(cfg["access"], "access", out), follower(cfg["eve"], "eve", out)]
    correlator = Correlator(cfg, server_ips, args.mode, firewall)
    logs = LogSizeMonitor(cfg["access"])
    LOG.info("Started mode=%s, network=host, ban=%ds", args.mode, BAN_SECONDS)
    try:
        logs.refresh(initial=True)
        while True:
            network.refresh()
            logs.refresh()
            for f in followers:
                f.step()
            for _ in range(15000):
                try:
                    src, line = out.get_nowait()
                except queue.Empty:
                    break
                if src == "access":
                    correlator.add_access(line)
                else:
                    correlator.add_eve(line)
            correlator.process_pending()
            time.sleep(.3)
    except KeyboardInterrupt:
        pass
    finally:
        logs.close()
        for f in followers:
            f.close()


if __name__ == "__main__":
    main()
