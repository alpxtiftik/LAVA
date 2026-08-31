#!/bin/bash
# LAVA Linux launcher (plug-and-play)
# Creates a virtual environment and starts the LAVA desktop UI.

set -u
cd "$(dirname "$0")/.."

echo "========================================="
echo "Starting LAVA UI (Linux)..."
echo "========================================="

# Make sure python3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 not found. Please install Python 3.10+."
    exit 1
fi

# On Debian/Kali based systems make sure python3-venv is installed
if command -v apt-get &> /dev/null; then
    if ! dpkg -s python3-venv &> /dev/null 2>&1; then
        echo "The python3-venv package is missing. Installing..."
        sudo apt-get update && sudo apt-get install -y python3-venv
    fi
fi

# Create the virtual environment
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi

# Activate the virtual environment
source .venv/bin/activate

# --- dependencies ---------------------------------------------------------------
# Are the essential libraries already importable in this venv?
_have_deps() {
    python3 - <<'PY' >/dev/null 2>&1
import importlib.util as u
raise SystemExit(0 if all(u.find_spec(m) for m in ("webview", "requests", "mcp")) else 1)
PY
}

# Quick reachability check for PyPI (4s) so we never hang when offline
_online() {
    python3 - <<'PY' >/dev/null 2>&1
import socket
socket.setdefaulttimeout(4)
try:
    socket.create_connection(("pypi.org", 443)).close()
except OSError:
    raise SystemExit(1)
PY
}

if _have_deps; then
    echo "[OK] Dependencies already installed - skipping update."
elif _online; then
    echo "Updating libraries (this can take a while on the first run)..."
    export PIP_DEFAULT_TIMEOUT=15
    pip install --upgrade pip --retries 1 -q
    pip install -r requirements.txt --retries 1
    pip install PyQt6 PyQtWebEngine qtpy --retries 1
    if _have_deps; then
        echo "[OK] Libraries updated."
    else
        echo "Error: required libraries could not be installed. Aborting."
        exit 1
    fi
else
    echo "[WARN] No internet connection - skipping the library update step."
    if ! _have_deps; then
        echo "Error: no internet connection and the required libraries (webview, requests, mcp)"
        echo "       are not installed yet. Connect to the internet once and re-run this script."
        exit 1
    fi
    echo "Continuing offline with the already-installed libraries."
fi

echo "[OK] Launching the LAVA UI..."
# --no-sandbox avoids a Chromium sandbox error when started as root
QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox" python3 src/gui/gui_main.py
