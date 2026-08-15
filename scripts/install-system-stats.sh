#!/usr/bin/env bash

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Dieses Skript muss als root ausgeführt werden."
  exit 1
fi

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

DATA_DIR="${DMS_DATA_DIR:-}"

# Wenn DMS_DATA_DIR nicht bereits als Umgebungsvariable
# gesetzt wurde, den Wert aus der Projekt-.env übernehmen.
if [ -z "${DATA_DIR}" ] && [ -f "${PROJECT_DIR}/.env" ]; then
  DATA_DIR="$(
    python3 - "${PROJECT_DIR}/.env" <<'PYENV'
from pathlib import Path
import sys

env_file = Path(sys.argv[1])

value = ""

for raw in env_file.read_text().splitlines():
    line = raw.strip()

    if not line or line.startswith("#") or "=" not in line:
        continue

    key, current = line.split("=", 1)

    if key.strip() != "DMS_DATA_DIR":
        continue

    current = current.strip()

    if (
        len(current) >= 2
        and current[0] == current[-1]
        and current[0] in ("'", '"')
    ):
        current = current[1:-1]

    value = current

print(value)
PYENV
  )"
fi

DATA_DIR="${DATA_DIR:-/data/dms}"

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

DEFAULT_FILE="/etc/default/dms-system-stats"

touch "${DEFAULT_FILE}"
chmod 644 "${DEFAULT_FILE}"

python3 - "${DEFAULT_FILE}" "${DATA_DIR}" <<'PYDEFAULT'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data_dir = sys.argv[2]

lines = path.read_text().splitlines()

out = []
replaced = False

for line in lines:
    if line.startswith("DMS_DATA_DIR="):
        if not replaced:
            out.append(f"DMS_DATA_DIR={data_dir}")
            replaced = True
        continue

    out.append(line)

if not replaced:
    out.append(f"DMS_DATA_DIR={data_dir}")

path.write_text(
    "\n".join(out).rstrip() + "\n"
)
PYDEFAULT

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
