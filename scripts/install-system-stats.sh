#!/usr/bin/env bash

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Dieses Skript muss als root ausgeführt werden."
  exit 1
fi

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

DATA_DIR="${DMS_DATA_DIR:-/data/dms}"

if [ ! -f "${PROJECT_DIR}/scripts/dms-system-stats" ]; then
  echo "Fehler: scripts/dms-system-stats fehlt."
  exit 1
fi

if [ ! -f "${PROJECT_DIR}/systemd/dms-system-stats.service" ]; then
  echo "Fehler: systemd/dms-system-stats.service fehlt."
  exit 1
fi

if [ ! -f "${PROJECT_DIR}/systemd/dms-system-stats.timer" ]; then
  echo "Fehler: systemd/dms-system-stats.timer fehlt."
  exit 1
fi

install -Dm755 \
  "${PROJECT_DIR}/scripts/dms-system-stats" \
  /usr/local/sbin/dms-system-stats

install -Dm644 \
  "${PROJECT_DIR}/systemd/dms-system-stats.service" \
  /etc/systemd/system/dms-system-stats.service

install -Dm644 \
  "${PROJECT_DIR}/systemd/dms-system-stats.timer" \
  /etc/systemd/system/dms-system-stats.timer

if [ ! -f /etc/default/dms-system-stats ]; then
  printf 'DMS_DATA_DIR=%s\n' "${DATA_DIR}" \
    > /etc/default/dms-system-stats

  chmod 644 /etc/default/dms-system-stats
fi

mkdir -p "${DATA_DIR}/status"

systemctl daemon-reload
systemctl enable --now dms-system-stats.timer
systemctl start dms-system-stats.service

echo
echo "DMS Systemstatus-Collector installiert."
echo "Datenverzeichnis: ${DATA_DIR}"
echo

systemctl --no-pager --full status \
  dms-system-stats.timer || true
