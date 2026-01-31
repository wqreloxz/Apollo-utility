#!/bin/bash
set -e
echo "[INFO] Installing Apollo..."
install -m755 apollo.py /usr/local/bin/apollo
mkdir -p ~/.apollo
echo "[SUCCESS] Apollo installed."
