#!/system/bin/sh
# Privacy Sentinel — BakaSU / KernelSU Manager Quick Action Button

MODDIR="${0%/*}"
CTL="${MODDIR}/bin/sentinelctl"
TOKEN_FILE="/data/adb/privacy_sentinel/run/webui.token"

echo "=== Privacy Sentinel Status ==="
if [ -x "$CTL" ]; then
  "$CTL" status
fi

if [ -f "$TOKEN_FILE" ]; then
  TOK="$(cat "$TOKEN_FILE")"
  echo ""
  echo "Local REST Endpoint : http://127.0.0.1:18917"
  echo "X-Sentinel-Token    : ${TOK}"
fi
