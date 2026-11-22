#!/usr/bin/env python3
"""Maintain the Supervisor limit for the Xray log, without reading log contents.

The guard sends this stdlib-only helper to the container's Python interpreter.
It also runs directly in tests, without Docker or any running Xray process.
"""
import configparser
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

MIN_LOG_BYTES = 100 * 1024 * 1024
SUPERVISOR_CONFIG = "/etc/supervisord.conf"


def supervisor_bytes(value):
    match = re.fullmatch(r"\+?(\d+)\s*(KB|MB|GB)?", value.strip(), re.I)
    if not match:
        raise ValueError("Invalid stdout_logfile_maxbytes; configuration left unchanged")
    return int(match[1]) * {None: 1, "KB": 1024, "MB": 1024 ** 2,
                           "GB": 1024 ** 3}[match[2].upper() if match[2] else None]


def upgrade_supervisor_log(text, log_path):
    config = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(";",))
    config.read_string(text)
    sections = [section for section in config.sections()
                if section.startswith("program:")
                and config.get(section, "stdout_logfile", fallback="") == log_path]
    if not sections:
        return text, {"status": "unsupported", "reason": "not_a_supervisor_stdout_log"}
    if len(sections) != 1:
        raise ValueError("Several Supervisor programs share the Xray log; configuration left unchanged")
    section = sections[0]
    limit = supervisor_bytes(config.get(section, "stdout_logfile_maxbytes", fallback="50MB"))
    result = {"status": "unchanged", "limit_bytes": limit, "program": section[8:]}
    # Supervisor uses zero for unlimited logging. Never lower a larger limit.
    if limit == 0 or limit >= MIN_LOG_BYTES:
        return text, result
    headers = list(re.finditer(r"(?m)^[ \t]*\[([^\]\r\n]+)\][^\r\n]*(?:\r?\n|$)", text))
    index = next(i for i, header in enumerate(headers) if header[1] == section)
    start = headers[index].end()
    end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
    body = text[start:end]
    option = re.compile(r"(?mi)^([ \t]*stdout_logfile_maxbytes[ \t]*[=:][ \t]*)"
                        r"[^;\r\n]*?([ \t]*(?:;[^\r\n]*)?\r?)$")
    replacement, count = option.subn(lambda match: match[1] + "100MB" + match[2], body)
    if count == 0:
        newline = "\r\n" if "\r\n" in text else "\n"
        first_option = re.search(r"(?m)^([ \t]*)[^\s;#\[][^\r\n]*[=:]", body)
        indent = first_option[1] if first_option else ""
        replacement = indent + "stdout_logfile_maxbytes=100MB" + newline + body
        # A section header at EOF may have no terminating newline.
        if start and not text[:start].endswith("\n"):
            replacement = newline + replacement
    result.update(status="changed", previous_limit_bytes=limit, limit_bytes=MIN_LOG_BYTES)
    return text[:start] + replacement + text[end:], result


def ensure_supervisor_log(path, log_path):
    try:
        path = Path(path).resolve(strict=True)
    except FileNotFoundError:
        return {"status": "unsupported", "reason": "supervisor_config_missing"}
    attributes = path.stat()
    if not stat.S_ISREG(attributes.st_mode):
        raise ValueError("Supervisor configuration must be a regular file")
    with path.open(encoding="utf-8", newline="") as file:
        original = file.read()
    updated, result = upgrade_supervisor_log(original, log_path)
    if result["status"] != "changed":
        return result
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="",
                                         dir=path.parent, prefix=".xray-guard-", delete=False) as file:
            temporary = Path(file.name)
            os.fchown(file.fileno(), attributes.st_uid, attributes.st_gid)
            os.fchmod(file.fileno(), stat.S_IMODE(attributes.st_mode))
            file.write(updated)
            file.flush()
            os.fsync(file.fileno())
        with path.open(encoding="utf-8", newline="") as file:
            if file.read() != original:
                raise ValueError("Supervisor configuration changed during log size check; retry later")
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return result


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: log_maintenance.py SUPERVISOR_CONFIG XRAY_LOG_PATH")
    try:
        result = ensure_supervisor_log(sys.argv[1], sys.argv[2])
    except configparser.Error:
        result = {"status": "error", "error": "Invalid Supervisor INI configuration"}
    except OSError as exc:
        result = {"status": "error", "error": os.strerror(exc.errno) if exc.errno else "File update failed"}
    except ValueError as exc:
        result = {"status": "error", "error": str(exc)}
    print(json.dumps(result))
    return 1 if result["status"] == "error" else 0


if __name__ == "__main__":
    sys.exit(main())
