#!/bin/sh
set -e

if [ ! -f /etc/wireguard/wg0.conf ]; then
  echo "[proxy-vpn] wireguard: /etc/wireguard/wg0.conf missing."
  echo "[proxy-vpn] Mount wireguard-config with wg0.conf (API will generate it later)."
  exec sleep infinity
fi

wg-quick down wg0 2>/dev/null || true
wg-quick up wg0
echo "[proxy-vpn] wireguard: wg0 is up"

# Periodically export real peer counters for API sampler.
while true; do
  if wg show wg0 dump > /etc/wireguard/wg_dump.txt.tmp 2>/dev/null; then
    mv /etc/wireguard/wg_dump.txt.tmp /etc/wireguard/wg_dump.txt
  fi
  sleep 10
done
