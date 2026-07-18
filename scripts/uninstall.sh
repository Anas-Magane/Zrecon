#!/usr/bin/env bash
set -euo pipefail

BINARY="zrecon"
INSTALL_PATH="/usr/local/bin/$BINARY"

if [ -f "$INSTALL_PATH" ]; then
  if [ -w "$INSTALL_PATH" ]; then
    rm "$INSTALL_PATH"
  else
    sudo rm "$INSTALL_PATH"
  fi
  echo "[-] $BINARY removed from $INSTALL_PATH"
else
  echo "[!] $BINARY not found at $INSTALL_PATH"
fi
