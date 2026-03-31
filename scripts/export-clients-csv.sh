#!/usr/bin/env bash
# Export merged client data (WireGuard + Xray) to CSV.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

OUTPUT_PATH="${OUTPUT_PATH:-exports/clients-export.csv}"
WG_DIR="${WG_DIR:-wireguard/conf}"
XRAY_DIR="${XRAY_DIR:-xray/clients}"

[ -d "${WG_DIR}" ] || die "WG directory not found: ${WG_DIR}"
[ -d "${XRAY_DIR}" ] || die "Xray clients directory not found: ${XRAY_DIR}"

mkdir -p "$(dirname "${OUTPUT_PATH}")"

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT

{
  printf 'name,wg_config_path,wg_address,wg_endpoint,xray_client_file,xray_uuid,xray_uri\n'

  found=0
  for wg_file in "${WG_DIR}"/*.conf; do
    [ -e "${wg_file}" ] || continue
    base="$(basename "${wg_file}")"
    name="${base%.conf}"

    # Skip server config.
    [ "${name}" = "wg0" ] && continue

    found=1
    wg_address="$(awk -F'= ' '/^Address/{print $2; exit}' "${wg_file}" | tr -d '\r')"
    wg_endpoint="$(awk -F'= ' '/^Endpoint/{print $2; exit}' "${wg_file}" | tr -d '\r')"

    xray_file="${XRAY_DIR}/${name}.txt"
    xray_uuid=""
    xray_uri=""
    if [ -f "${xray_file}" ]; then
      xray_uuid="$(awk -F': ' '/^UUID:/{print $2; exit}' "${xray_file}" | tr -d '\r')"
      xray_uri="$(awk '/^vless:\/\//{print; exit}' "${xray_file}" | tr -d '\r')"
    fi

    # Basic CSV escaping for quotes.
    esc_wg_file="$(printf '%s' "${wg_file}" | sed 's/"/""/g')"
    esc_wg_address="$(printf '%s' "${wg_address}" | sed 's/"/""/g')"
    esc_wg_endpoint="$(printf '%s' "${wg_endpoint}" | sed 's/"/""/g')"
    esc_xray_file="$(printf '%s' "${xray_file}" | sed 's/"/""/g')"
    esc_xray_uuid="$(printf '%s' "${xray_uuid}" | sed 's/"/""/g')"
    esc_xray_uri="$(printf '%s' "${xray_uri}" | sed 's/"/""/g')"

    printf '"%s","%s","%s","%s","%s","%s","%s"\n' \
      "${name}" \
      "${esc_wg_file}" \
      "${esc_wg_address}" \
      "${esc_wg_endpoint}" \
      "${esc_xray_file}" \
      "${esc_xray_uuid}" \
      "${esc_xray_uri}"
  done

  [ "${found}" -eq 1 ] || die "No client .conf files found in ${WG_DIR}."
} > "${tmp}"

mv "${tmp}" "${OUTPUT_PATH}"
chmod 600 "${OUTPUT_PATH}"
log "CSV exported: ${OUTPUT_PATH}"
