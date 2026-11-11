#!/system/bin/sh
# Emergency CLI helper to flush or inspect Privacy Sentinel netfilter chains on POCO X6 5G (Linux 5.10)

case "$1" in
  flush)
    for T in "iptables -w 2" "ip6tables -w 2"; do
      $T -F SENTINEL_OUT 2>/dev/null
      $T -F SENTINEL_SLEEP 2>/dev/null
    done
    iptables -w 2 -t nat -F SENTINEL_PROXY 2>/dev/null
    echo "[sentinel-fw] All SENTINEL chains flushed (Safe Fail-Open)."
    ;;
  status|*)
    echo "=== IPv4 Filter (SENTINEL_OUT / SENTINEL_SLEEP) ==="
    iptables -w 2 -L SENTINEL_OUT -n -v 2>/dev/null || echo "(chain not initialized)"
    iptables -w 2 -L SENTINEL_SLEEP -n -v 2>/dev/null
    echo "=== IPv4 NAT (SENTINEL_PROXY) ==="
    iptables -w 2 -t nat -L SENTINEL_PROXY -n -v 2>/dev/null
    ;;
esac
