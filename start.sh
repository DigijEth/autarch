#!/bin/bash
# AUTARCH Launcher
# Starts the GTK desktop launcher which manages the daemon and web server

DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -f "$DIR/venv/bin/python" ]; then
    exec "$DIR/venv/bin/python" "$DIR/launcher.py" "$@"
else
    exec python3 "$DIR/launcher.py" "$@"
fi
