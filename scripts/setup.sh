#!/usr/bin/env bash
set -euo pipefail

# apkX setup script (v3.2)
# Installs prerequisites (Debian/Ubuntu), optional tools (apk-mitm, apkeep), builds and runs the web server.

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

echo "[1/5] Installing system packages..."
$SUDO apt-get update -y
$SUDO apt-get install -y --no-install-recommends \
  golang-go openjdk-17-jre-headless unzip zip curl git python3 python3-pip

# Ensure go is available
if ! command -v go >/dev/null 2>&1; then
  echo "Go not found in PATH. Please install Go 1.21+ and re-run." >&2
  exit 1
fi

echo "[2/5] Installing optional tools (apk-mitm, apkeep)..."
# apkeep
pip3 install --upgrade apkeep
# node + apk-mitm
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_18.x | $SUDO -E bash -
  $SUDO apt-get install -y nodejs
fi
$SUDO npm install -g apk-mitm || true

echo "[3/5] Building apkX web server..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

go mod download

go build -o apkx-web ./cmd/server/main.go

mkdir -p web-data/uploads web-data/reports web-data/downloads

echo "[4/5] Opening firewall (9090)..."
if command -v ufw >/dev/null 2>&1; then
  $SUDO ufw allow 9090 || true
fi

echo "[5/5] Starting server on :9090 with MITM enabled (Ctrl+C to stop)..."
./apkx-web -addr :9090 -mitm
