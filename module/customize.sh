#!/system/bin/sh
# Privacy Sentinel v2.0 — Flash-Time Installer & In-Place Upgrader (BakaSU / KernelSU / APatch)
SKIPUNZIP=0

ui_print "──────────────────────────────────────────────"
ui_print "  Privacy Sentinel v2.0.0 Mobile (Android 17)"
ui_print "  Target: arm64-v8a • Linux 5.10+ • HyperOS 4"
ui_print "──────────────────────────────────────────────"

ARCH_PROP="$(getprop ro.product.cpu.abi)"
DEVICE_CODE="$(getprop ro.product.device)"
KERNEL_VER="$(uname -r)"

ui_print "• Detected ABI    : ${ARCH_PROP}"
ui_print "• Detected Device : ${DEVICE_CODE:-unknown}"
ui_print "• Detected Kernel : ${KERNEL_VER}"

case "$ARCH_PROP" in
  arm64-v8a*|aarch64*)
    ui_print "• Architecture OK (64-bit ARM)"
    ;;
  x86_64*)
    ui_print "• Architecture OK (64-bit x86_64 AVD)"
    ;;
  *)
    abort "! Unsupported 32-bit only architecture: ${ARCH_PROP}"
    ;;
esac

if [ "$KSU" = "true" ]; then
  ui_print "• Root Environment: KernelSU / BakaSU (ver: ${KSU_VER_CODE:-detected})"
fi

if [ -d /data/adb/modules/privacy_sentinel ]; then
  ui_print "• Existing module : Upgrading v1.x -> v2.0.0 Mobile in-place"
  ui_print "  -> Existing rules & policies in /data/adb/privacy_sentinel preserved"
fi

if [ -e /proc/susfs ] || [ -x /data/adb/ksu/bin/ksu_susfs ]; then
  ui_print "• SuSFS Built-in  : Detected (automatic path cloaking enabled)"
fi

if [ -d /data/adb/modules/tricky_store ] || [ -d /data/adb/tricky_store ]; then
  ui_print "• Tricky Store    : Detected (Zero-Touch exemptions active)"
fi

if [ -d /data/adb/modules/playintegrityfix ]; then
  ui_print "• PlayIntegrityFix: Detected (DLCLOSE_MODULE_LIBRARY protection active)"
fi

mkdir -p /data/adb/privacy_sentinel/run
mkdir -p /data/adb/privacy_sentinel/config
mkdir -p /data/adb/privacy_sentinel/logs
chmod 0711 /data/adb/privacy_sentinel
chmod 0711 /data/adb/privacy_sentinel/run
chmod 0700 /data/adb/privacy_sentinel/config
chmod 0700 /data/adb/privacy_sentinel/logs

set_perm_recursive "$MODPATH/bin" 0 0 0755 0755
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/boot-completed.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755

# Hot-sync WebUI v2.0 into active module directory if upgrading live over v1.x
if [ -d /data/adb/modules/privacy_sentinel/webroot ]; then
  cp -rf "$MODPATH/webroot/." /data/adb/modules/privacy_sentinel/webroot/ 2>/dev/null || true
  ui_print "  -> Hot-updated Mobile WebUI v2.0 immediately!"
fi

# Note: Do NOT override permissions on $MODPATH/webroot — KernelSU sets webroot SELinux context automatically!

if [ -f "$MODPATH/apk/PrivacySentinelVector.apk" ]; then
  ui_print "• Updating Vector (LibXposed API 102) companion APK to v2.0..."
  pm install -r "$MODPATH/apk/PrivacySentinelVector.apk" >/dev/null 2>&1 && \
    ui_print "  -> Installed org.privacysentinel.vector v2.0" || \
    ui_print "  -> Deferred APK update to boot-completed.sh"
fi

ui_print "• Upgrade v2.0.0 ready! Reboot recommended (WebUI v2.0 active now)."
ui_print "──────────────────────────────────────────────"
