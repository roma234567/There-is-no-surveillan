#!/system/bin/sh
# Privacy Sentinel — Clean Teardown on Module Removal

pkill -f "sentineld" 2>/dev/null

# Flush and delete isolated iptables / ip6tables chains (Linux 5.10)
for T in "iptables -w 2" "ip6tables -w 2"; do
  $T -D OUTPUT -j SENTINEL_OUT 2>/dev/null
  $T -D OUTPUT -j SENTINEL_SLEEP 2>/dev/null
  $T -F SENTINEL_OUT 2>/dev/null
  $T -X SENTINEL_OUT 2>/dev/null
  $T -F SENTINEL_SLEEP 2>/dev/null
  $T -X SENTINEL_SLEEP 2>/dev/null
done
iptables -w 2 -t nat -D OUTPUT -j SENTINEL_PROXY 2>/dev/null
iptables -w 2 -t nat -F SENTINEL_PROXY 2>/dev/null
iptables -w 2 -t nat -X SENTINEL_PROXY 2>/dev/null

# Remove nftables table if used
nft delete table inet privacy_sentinel 2>/dev/null

# Remove AOSP IntentFirewall rules & runtime directory
rm -f /data/system/ifw/privacy_sentinel.xml
rm -rf /data/adb/privacy_sentinel

# Uninstall Vector companion APK
pm uninstall org.privacysentinel.vector >/dev/null 2>&1
