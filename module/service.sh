#!/system/bin/sh
# Privacy Sentinel — service.sh (late_start service)
# Launches sentineld under UID 0 in a dedicated cgroup v2 outside Android 17 MemoryLimiter & Freezer.

MODDIR="${0%/*}"
BASE_DIR="/data/adb/privacy_sentinel"
LOG_FILE="${BASE_DIR}/logs/sentineld.log"
DAEMON_BIN="${MODDIR}/bin/sentineld"

# Ensure dedicated cgroup outside /sys/fs/cgroup/uid_* so Android 17 MemoryLimiter & Freezer ignore sentineld
if [ -d /sys/fs/cgroup ]; then
  mkdir -p /sys/fs/cgroup/privacy_sentinel 2>/dev/null
fi

if [ ! -x "$DAEMON_BIN" ]; then
  echo "[service.sh] sentineld binary missing at ${DAEMON_BIN}" >> "$LOG_FILE"
  exit 0
fi

# Kill stale instance if any
pkill -f "privacy_sentinel/bin/sentineld" 2>/dev/null

# Start sentineld strictly bound to 127.0.0.1:18917 + UNIX sockets
nohup "$DAEMON_BIN" \
  --base-dir "$BASE_DIR" \
  --webroot "${MODDIR}/webroot" \
  --bind 127.0.0.1 \
  --port 18917 >> "$LOG_FILE" 2>&1 &

DAEMON_PID=$!
if [ -d /sys/fs/cgroup/privacy_sentinel ] && [ -n "$DAEMON_PID" ]; then
  echo "$DAEMON_PID" > /sys/fs/cgroup/privacy_sentinel/cgroup.procs 2>/dev/null
fi
echo "$DAEMON_PID" > "${BASE_DIR}/run/sentineld.pid"
