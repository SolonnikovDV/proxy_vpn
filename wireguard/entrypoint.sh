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
exec tail -f /dev/null
