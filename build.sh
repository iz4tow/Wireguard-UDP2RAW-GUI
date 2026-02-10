#!/usr/bin/env bash
set -euo pipefail

# build.sh - package DodgeVPN release bundle
# Expected files in current directory:
#   - wg_GUI_udp2raw_MTU.go
#   - install_wg_with_udp2raw.sh

APP_NAME="DodgeVPN"
GO_FILE="wg_GUI_udp2raw_MTU.go"
BIN_NAME="wg_GUI_udp2raw_MTU"
INSTALLER="install_wg_with_udp2raw.sh"

# Resolve script dir so it works from anywhere
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "[+] Preparing ${APP_NAME} folder..."
rm -rf "${APP_NAME}"
mkdir -p "${APP_NAME}"

echo "[+] Building Go binary..."
if ! command -v go >/dev/null 2>&1; then
  echo "[!] go not found in PATH"
  exit 1
fi
if [[ ! -f "${GO_FILE}" ]]; then
  echo "[!] Missing ${GO_FILE} in ${SCRIPT_DIR}"
  exit 1
fi

go build -ldflags="-s -w" -trimpath -o "${BIN_NAME}" "${GO_FILE}"

echo "[+] Moving binary into ${APP_NAME}/ ..."
mv -f "${BIN_NAME}" "${APP_NAME}/"

echo "[+] Copying installer into ${APP_NAME}/ ..."
if [[ ! -f "${INSTALLER}" ]]; then
  echo "[!] Missing ${INSTALLER} in ${SCRIPT_DIR}"
  exit 1
fi
cp -f "${INSTALLER}" "${APP_NAME}/"

echo "[+] Making installer executable..."
chmod +x "${APP_NAME}/${INSTALLER}"

echo "[+] Creating tar.gz..."
TAR_NAME="${APP_NAME}.tar.gz"
rm -f "${TAR_NAME}"
tar -czf "${TAR_NAME}" "${APP_NAME}"

echo "[OK] Done: ${SCRIPT_DIR}/${TAR_NAME}"

