#!/system/bin/sh
# Privacy Sentinel — post-fs-data.sh
# Runs early before Zygote: manages YABP-safe bootloop watchdog & BakaSU SuSFS hiding.

MODDIR="${0%/*}"
BASE_DIR="/data/adb/privacy_sentinel"
RUN_DIR="${BASE_DIR}/run"
ATTEMPT_FILE="${BASE_DIR}/boot_attempts"
SAFE_FLAG="${BASE_DIR}/safe_bypass"

mkdir -p "$RUN_DIR" "${BASE_DIR}/config" "${BASE_DIR}/logs"
chmod 0711 "$BASE_DIR" "$RUN_DIR"

# 1. Bootloop Watchdog (cooperates with Yet Another Bootloop Protector)
ATTEMPTS=0
if [ -f "$ATTEMPT_FILE" ]; then
  ATTEMPTS=$(cat "$ATTEMPT_FILE" 2>/dev/null || echo 0)
fi
ATTEMPTS=$((ATTEMPTS + 1))
echo "$ATTEMPTS" > "$ATTEMPT_FILE"

if [ "$ATTEMPTS" -ge 3 ]; then
  echo "1" > "$SAFE_FLAG"
  echo "[$(date)] Boot watchdog triggered Safe Bypass after ${ATTEMPTS} incomplete boots" >> "${BASE_DIR}/logs/watchdog.log"
  # Remove IFW rules immediately so ActivityManagerService starts completely clean
  rm -f /data/system/ifw/privacy_sentinel.xml
fi

# 2. Register module runtime paths in BakaSU / SuSFS so root-detecting apps never see them
for SUS_BIN in /data/adb/ksu/bin/ksu_susfs /system/bin/ksu_susfs; do
  if [ -x "$SUS_BIN" ]; then
    "$SUS_BIN" add_sus_path "$BASE_DIR" >/dev/null 2>&1
    "$SUS_BIN" add_sus_path "/data/media/0/.sentinel_sandbox" >/dev/null 2>&1
    break
  fi
done
