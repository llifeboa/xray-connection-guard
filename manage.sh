#!/usr/bin/env bash
set -euo pipefail
OP="${1:-help}"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
UNIT=xray-connection-guard
CFG=/etc/xray-connection-guard/config.json
SCRIPT=/opt/xray-connection-guard/guard.py
INSPECTOR=/opt/xray-connection-guard/inspector.py
CONFIGURATOR=/opt/xray-connection-guard/configure_guard.py
INSPECTOR_UNIT=xray-ndpi.service
QUEUE_UNIT=xray-connection-guard-queue.service
OVERRIDE=/etc/systemd/system/xray-connection-guard.service.d/mode.conf
if (( EUID != 0 )); then echo 'Run as root / sudo'; exit 1; fi
install_tools() {
  local missing=0 tool
  for tool in python3 nft ss ip; do
    command -v "$tool" >/dev/null || missing=1
  done
  if command -v python3 >/dev/null; then
    python3 -c 'import yaml' >/dev/null 2>&1 || missing=1
  fi
  if (( missing )); then
    command -v apt-get >/dev/null || { echo 'Install python3, python3-yaml, nftables and iproute2'; exit 1; }
    apt-get update
    apt-get install -y python3 python3-yaml nftables iproute2
  fi
}
start_inspector() {
  python3 "$INSPECTOR" install --config "$CFG"
  systemctl daemon-reload
  stop_old
  systemctl enable "$INSPECTOR_UNIT"
  systemctl restart "$QUEUE_UNIT"
  systemctl restart "$INSPECTOR_UNIT"
  systemctl is-active --quiet "$INSPECTOR_UNIT" || { journalctl -u "$INSPECTOR_UNIT" -n 50 --no-pager; exit 1; }
}
validate() {
  python3 "$SCRIPT" --config "$CFG" --check "$@"
}
write_mode() {
  local mode="$1" extra=""
  [[ "$mode" == enforce ]] && extra=' --allow-ban'
  mkdir -p "$(dirname "$OVERRIDE")"
  cat > "$OVERRIDE" <<EOF
[Service]
ExecStart=
ExecStart=/usr/bin/python3 -u $SCRIPT --config $CFG --mode $mode$extra
EOF
  systemctl daemon-reload
}
stop_old() {
  if systemctl list-unit-files xray-p2p-guard.service --no-legend 2>/dev/null | grep -q xray-p2p-guard.service; then
    systemctl disable --now xray-p2p-guard.service || true
    echo '[guard] Previous panel-API guard stopped/disabled'
  fi
}
case "$OP" in
  install)
    install_tools
    install -d -m 755 /opt/xray-connection-guard
    install -d -m 700 /etc/xray-connection-guard
    install -d -m 700 /var/log/xray-connection-guard
    if [[ -f "$SCRIPT" ]]; then
      cp -a "$SCRIPT" "$SCRIPT.bak.$(date +%Y%m%d%H%M%S)"
    fi
    install -m 755 "$ROOT/src/guard.py" "$SCRIPT"
    install -m 755 "$ROOT/src/log_maintenance.py" /opt/xray-connection-guard/log_maintenance.py
    install -m 755 "$ROOT/src/inspector.py" "$INSPECTOR"
    install -m 755 "$ROOT/src/tun_network.py" /opt/xray-connection-guard/tun_network.py
    install -m 755 "$ROOT/src/install_suricata.py" /opt/xray-connection-guard/install_suricata.py
    install -m 755 "$ROOT/src/configure_guard.py" "$CONFIGURATOR"
    if [[ ! -f "$CFG" ]]; then
      if [[ -f /etc/xray-p2p-guard/config.json ]]; then
        SRC=/etc/xray-p2p-guard/config.json CFG_PATH="$CFG" python3 - <<'PY'
import json, os
src=json.load(open(os.environ['SRC'], encoding='utf-8'))
keep=('eve','access','xray_timezone','signatures',
      'max_match_delay_seconds','correlation_buffer_seconds','window_seconds',
      'min_distinct_peers','min_distinct_flows')
new={k:src[k] for k in keep if k in src}
new['audit_path']='/var/log/xray-connection-guard/audit.jsonl'
new['firewall']={'host_network':True, 'ban_seconds':600, 'allowlist_cidrs':[]}
with open(os.environ['CFG_PATH'],'w') as f: json.dump(new,f,indent=2,ensure_ascii=False)
print('Copied read-only detection settings from old guard; panel credentials/users omitted')
PY
      else
        install -m 600 "$ROOT/config/config.example.json" "$CFG"
      fi
    else
      echo '[guard] Existing configuration preserved'
    fi
    CFG_PATH="$CFG" python3 - <<'PY'
import json, os, shutil, tempfile, time
from pathlib import Path
path=Path(os.environ['CFG_PATH'])
cfg=json.loads(path.read_text(encoding='utf-8'))
before=json.dumps(cfg, sort_keys=True)
fw=cfg.get('firewall', {})
cfg.pop('server_ips', None)
fw.pop('tcp_ports', None)
fw.pop('udp_ports', None)
if fw.get('ban_seconds', 60) == 60:
    fw['ban_seconds']=600
if json.dumps(cfg, sort_keys=True) != before:
    backup=path.with_name(path.name + '.bak.' + str(time.time_ns()))
    shutil.copy2(path, backup)
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                     dir=path.parent, delete=False) as file:
        temporary=Path(file.name)
        try:
            json.dump(cfg, file, indent=2, ensure_ascii=False)
            file.write('\n')
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    print(f'[guard] Updated configuration; backup: {backup}')
PY
    chmod 600 "$CFG"
    python3 "$CONFIGURATOR" --config "$CFG" --defer "${@:2}"
    validate
    python3 /opt/xray-connection-guard/install_suricata.py --config "$CFG"
    install -m 644 "$ROOT/systemd/xray-connection-guard.service" /etc/systemd/system/xray-connection-guard.service
    systemctl daemon-reload
    echo '[guard] Installed. Apply Xray logging and mark=1481785689, or use enable --inspection-interface NAME for TUN inspection.'
    ;;
  monitor)
    python3 "$CONFIGURATOR" --config "$CFG" "${@:2}"
    validate --mode monitor
    start_inspector
    write_mode monitor
    systemctl enable "$UNIT"
    systemctl restart "$UNIT"
    echo '[guard] Monitoring only; no IPs banned.'
    ;;
  enable)
    python3 "$CONFIGURATOR" --config "$CFG" "${@:2}"
    validate --mode enforce --allow-ban
    command -v nft >/dev/null || { echo 'nft missing: apt install nftables'; exit 1; }
    command -v ss >/dev/null || { echo 'ss missing: apt install iproute2'; exit 1; }
    start_inspector
    write_mode enforce
    systemctl enable "$UNIT"
    systemctl restart "$UNIT"
    systemctl is-active --quiet "$UNIT" || { journalctl -u "$UNIT" -n 50 --no-pager; exit 1; }
    echo '[guard] ENFORCE ON: 10-minute IP bans on all ports and protocols; TCP sockets force-closed; node IPs refreshed every 10 minutes.'
    ;;
  off)
    systemctl disable --now "$UNIT" 2>/dev/null || true
    if nft list table inet xray_client_ban >/dev/null 2>&1; then
      nft delete table inet xray_client_ban
    fi
    echo '[guard] Off, its own bans cleared; Suricata and Xray unchanged.'
    ;;
  status)
    systemctl status "$UNIT" --no-pager -l || true
    nft list table inet xray_client_ban 2>/dev/null || true
    ;;
  bans)
    nft list set inet xray_client_ban clients_v4 2>/dev/null || true
    nft list set inet xray_client_ban clients_v6 2>/dev/null || true
    tail -n 15 /var/log/xray-connection-guard/audit.jsonl 2>/dev/null || true
    ;;
  *)
    echo 'Usage: sudo bash manage.sh install|monitor|enable|off|status|bans'
    echo 'Options: --container NAME; --inspection-interface NAME or --inspection-mark'
    exit 2
    ;;
esac
