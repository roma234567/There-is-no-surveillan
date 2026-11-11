#!/system/bin/sh
# Privacy Sentinel — boot-completed.sh
# Resets bootloop watchdog once Android 17 system_server is stably running.

MODDIR="${0%/*}"
BASE_DIR="/data/adb/privacy_sentinel"

# Install Vector Xposed companion APK if not yet installed during flash
if [ -f "${MODDIR}/apk/PrivacySentinelVector.apk" ]; then
  if ! pm path org.privacysentinel.vector >/dev/null 2>&1; then
    pm install -r "${MODDIR}/apk/PrivacySentinelVector.apk" >/dev/null 2>&1
  fi
fi

# Wait 45 seconds of stable uptime after sys.boot_completed=1 before resetting watchdog counter
sleep 45
if [ "$(getprop sys.boot_completed)" = "1" ]; then
  echo "0" > "${BASE_DIR}/boot_attempts"
  rm -f "${BASE_DIR}/safe_bypass"
fi
