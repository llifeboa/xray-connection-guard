#!/usr/bin/env python3
"""Discover the running Xray access log and timezone; fill the guard configuration."""
import argparse
import copy
import io
import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo

import guard
from inspector import atomic_write


class DiscoveryError(RuntimeError):
    pass


@dataclass
class Process:
    pid: int
    directory: Path
    mount_namespace: str

    @property
    def root(self):
        return self.directory / "root"


def processes(proc=Path("/proc")):
    network = os.readlink(proc / "self/ns/net")
    found = []
    for directory in proc.iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            binary = Path(os.readlink(directory / "exe")).name.removesuffix(" (deleted)")
            if not re.fullmatch(r"(?:xray(?:[-_.].*)?|rw-core)", binary, re.I):
                continue
            if os.readlink(directory / "ns/net") != network:
                continue
            found.append(Process(int(directory.name), directory, os.readlink(directory / "ns/mnt")))
        except (OSError, ValueError):
            continue  # A process may exit while /proc is being scanned.
    return found


def containers():
    if not shutil.which("docker"):
        return []
    try:
        result = subprocess.run(["docker", "ps", "-q"], capture_output=True, text=True, timeout=15)
        if result.returncode or not result.stdout.strip():
            return []
        # Query only metadata; never collect container environment variables or credentials.
        template = ('{"name":{{json .Name}},"image":{{json .Config.Image}},'
                    '"pid":{{.State.Pid}},"network":{{json .HostConfig.NetworkMode}}}')
        result = subprocess.run(["docker", "inspect", "--format", template, *result.stdout.split()],
                                capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise DiscoveryError("Cannot inspect running Docker containers")
        return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    except (OSError, subprocess.SubprocessError) as exc:
        raise DiscoveryError(f"Cannot query Docker: {exc}") from exc


def root_file(root, absolute):
    """Resolve an absolute symlink inside the process root, rather than the host root."""
    path = Path(absolute)
    for _ in range(20):
        candidate = root / str(path).lstrip("/")
        if not candidate.is_symlink():
            return candidate
        target = Path(os.readlink(candidate))
        path = target if target.is_absolute() else path.parent / target
    raise DiscoveryError(f"Too many symlinks: {absolute}")


def tail_has_access(path):
    try:
        with path.open("rb") as file:
            file.seek(0, 2)
            file.seek(max(0, file.tell() - 16384))
            data = file.read().decode("utf-8", errors="replace")
        return any(guard.ACCESS_RE.search(line) for line in data.splitlines())
    except OSError:
        return False


def xlogs_path(root):
    helper = root_file(root, "/usr/local/bin/xlogs")
    if not helper.is_file():
        return None
    for line in helper.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            tokens = shlex.split(line, comments=True)
        except ValueError:
            continue
        tail = next((n for n, token in enumerate(tokens) if Path(token).name == "tail"), None)
        if tail is not None:
            for token in tokens[tail + 1:]:
                if token.startswith("/") and "$" not in token and root_file(root, token).is_file():
                    return token
    # Older Remnawave images use supervisor rather than a plain tail helper.
    for path in ("/var/log/xray/current", "/var/log/supervisor/xray.out.log",
                 "/var/log/supervisor/xray.log"):
        if root_file(root, path).is_file():
            return path
    return None


def access_paths(process):
    found = set()
    try:
        descriptors = list((process.directory / "fd").iterdir())
    except OSError:
        descriptors = []
    for descriptor in descriptors:
        try:
            target = os.readlink(descriptor)
            if not target.startswith("/") or target.endswith(" (deleted)"):
                continue
            name = Path(target).name.lower()
            if not ("access" in name or name.endswith(".log")):
                continue
            path = root_file(process.root, target)
            if path.is_file() and ("access" in name or tail_has_access(path)):
                found.add(target)
        except OSError:
            continue
    if not found:
        # Xray creates the file at startup, but closes its descriptor when idle.
        for path in ("/var/lib/marzban/access.log", "/var/log/xray/access.log"):
            if root_file(process.root, path).is_file():
                found.add(path)
                break
    return found


def discover_source(available, inventory, container=None):
    mounted = {}
    for item in inventory:
        name = item["name"].lstrip("/")
        try:
            namespace = os.readlink(f"/proc/{item['pid']}/ns/mnt")
        except OSError:
            continue
        mounted[namespace] = dict(item, name=name)
    candidates = {}
    for process in available:
        node = mounted.get(process.mount_namespace)
        if container and (node is None or node["name"] != container):
            continue
        if node and node["network"] != "host":
            raise DiscoveryError(f"Xray container {node['name']} must use network_mode: host")
        path = xlogs_path(process.root) if node else None
        paths = {path} if path else access_paths(process)
        for path in paths:
            if node:
                source = {"type": "docker", "container": node["name"], "path": path}
            else:
                # A host file must refer to the same file Xray has open.
                try:
                    if not Path(path).samefile(root_file(process.root, path)):
                        continue
                except OSError:
                    continue
                source = {"type": "file", "path": path}
            candidates[json.dumps(source, sort_keys=True)] = (source, process)
    if len(candidates) == 1:
        return next(iter(candidates.values()))
    if not candidates:
        raise DiscoveryError("Xray access log not found. Start Xray with access logging enabled "
                             "and Docker network_mode: host, then run manage.sh enable")
    choices = [json.loads(key) for key in sorted(candidates)]
    raise DiscoveryError(f"Several Xray access logs found: {json.dumps(choices)}. "
                         "Select a node with manage.sh enable --container NAME")


def timezone(process):
    environment = (process.directory / "environ").read_bytes().split(b"\0")
    value = next((entry[3:].decode("utf-8") for entry in environment if entry.startswith(b"TZ=")), None)
    if value is not None:
        value = value.removeprefix(":")
        if value in ("", "UTC"):
            return "UTC", None
        paths = [value] if value.startswith("/") else [
            prefix + value for prefix in ("/usr/share/zoneinfo/", "/usr/share/lib/zoneinfo/",
                                         "/usr/lib/locale/TZ/", "/etc/zoneinfo/")]
        label = value
    else:
        paths, label = ["/etc/localtime"], "localtime"
    for path in paths:
        try:
            file = root_file(process.root, path)
            data = file.read_bytes()
            ZoneInfo.from_file(io.BytesIO(data))
            if label == "localtime" and "/zoneinfo/" in str(file):
                label = str(file).split("/zoneinfo/", 1)[1]
            return label, data
        except FileNotFoundError:
            continue
        except ValueError:
            continue
    # Go's time.Local uses UTC when TZ or /etc/localtime cannot be loaded.
    return "UTC", None


def configure(path, container=None):
    path = path.resolve()
    config = json.loads(path.read_text(encoding="utf-8"))
    selected = container or config.get("xray_container")
    source, process = discover_source(processes(), containers(), selected)
    label, data = timezone(process)
    updated = copy.deepcopy(config)
    updated.update(access=source, xray_timezone="UTC", xray_timezone_name=label)
    if container:
        updated["xray_container"] = container
    guard.validate(updated)
    if data is not None:
        target = path.parent / "xray-timezone.tzif"
        timezone_changed = not target.is_file() or target.read_bytes() != data
        atomic_write(target, data, 0o600)
        updated["xray_timezone"] = str(target)
    else:
        timezone_changed = False
    before = {key: config.get(key) for key in ("access", "xray_timezone", "xray_timezone_name")}
    after = {key: updated[key] for key in before}
    atomic_write(path, json.dumps(updated, ensure_ascii=False, indent=2) + "\n", 0o600)
    if before != after or timezone_changed:
        print(f"[guard config] Changed: old={json.dumps(before)} new={json.dumps(after)}; "
              f"timezone_rules_changed={timezone_changed}")
    else:
        print(f"[guard config] Detected: {json.dumps(after)}; unchanged")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/xray-connection-guard/config.json", type=Path)
    parser.add_argument("--container", help="Select a node if several Xray containers are running")
    parser.add_argument("--defer", action="store_true", help="Allow detection to wait until enable")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run as root")
    try:
        configure(args.config, args.container)
    except DiscoveryError as exc:
        if args.defer:
            print(f"[guard config] Detection deferred until enable: {exc}")
        else:
            parser.exit(1, f"[guard config] {exc}\n")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"[guard config] {exc}\n")


if __name__ == "__main__":
    main()
