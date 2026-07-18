#!/usr/bin/env bash
set -euo pipefail

BINARY="zrecon"
INSTALL_DIR="/usr/local/bin"

if ! command -v go &>/dev/null; then
  echo "Error: Go is not installed." >&2
  exit 1
fi

echo "[*] Building $BINARY..."
go build -ldflags="-s -w" -o "bin/$BINARY" .

echo "[*] Installing to $INSTALL_DIR/$BINARY..."
if [ -w "$INSTALL_DIR" ]; then
  cp "bin/$BINARY" "$INSTALL_DIR/$BINARY"
else
  sudo cp "bin/$BINARY" "$INSTALL_DIR/$BINARY"
fi

echo "[+] $BINARY installed successfully."
echo "[+] Run: $BINARY --help"
