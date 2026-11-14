#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# nano-bench-hoststat: one CSV row every 5 s until killed:
#   unix_ts,cpu_busy_pct,mem_used_pct,disk_used_pct,load1,net_rx_bytes,net_tx_bytes
# disk = the filesystem holding /var/lib/docker (nano data). No secrets.
exec -a nano-bench-hoststat bash -c '
out="$1"; echo "unix_ts,cpu_busy_pct,mem_used_pct,disk_used_pct,load1,net_rx_bytes,net_tx_bytes" > "$out"
iface=$(ip -o -4 route show to default | awk "{print \$5}" | head -1)
read -r _ u n s i w q sq st _ < /proc/stat; pt=$((u+n+s+i+w+q+sq+st)); pi=$((i+w))
while sleep 5; do
  read -r _ u n s i w q sq st _ < /proc/stat; t=$((u+n+s+i+w+q+sq+st)); id=$((i+w))
  busy=$(awk -v dt=$((t-pt)) -v di=$((id-pi)) "BEGIN{printf \"%.1f\", (dt>0)?100*(dt-di)/dt:0}"); pt=$t; pi=$id
  mem=$(awk "/MemTotal/{t=\$2}/MemAvailable/{a=\$2}END{printf \"%.1f\", 100*(t-a)/t}" /proc/meminfo)
  disk=$(df -P /var/lib/docker 2>/dev/null | awk "NR==2{gsub(\"%\",\"\",\$5);print \$5}")
  load=$(cut -d" " -f1 /proc/loadavg)
  rx=$(cat /sys/class/net/$iface/statistics/rx_bytes); tx=$(cat /sys/class/net/$iface/statistics/tx_bytes)
  echo "$(date +%s),$busy,$mem,$disk,$load,$rx,$tx" >> "$out"
done' nano-bench-hoststat "$1"
