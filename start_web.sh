#!/bin/bash
# AUTARCH Web Dashboard — install & start as systemd service
# Usage: bash start_web.sh [stop|restart|status]

set -e

SERVICE="autarch-web"
SERVICE_SRC="$(dirname "$(readlink -f "$0")")/scripts/autarch-web.service"
SERVICE_DST="/etc/systemd/system/${SERVICE}.service"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; RESET='\033[0m'

action="${1:-start}"

case "$action" in
  stop)
    sudo systemctl stop "$SERVICE" 2>/dev/null && echo -e "${GREEN}[+] Stopped${RESET}" || echo -e "${RED}[!] Not running${RESET}"
    exit 0
    ;;
  restart)
    sudo systemctl restart "$SERVICE" && echo -e "${GREEN}[+] Restarted${RESET}"
    exit 0
    ;;
  status)
    systemctl status "$SERVICE" --no-pager 2>/dev/null || echo -e "${RED}[!] Service not installed${RESET}"
    exit 0
    ;;
  start) ;; # fall through
  *)
    echo "Usage: $0 [start|stop|restart|status]"
    exit 1
    ;;
esac

# Install service file if missing or outdated
if [ ! -f "$SERVICE_DST" ] || ! diff -q "$SERVICE_SRC" "$SERVICE_DST" >/dev/null 2>&1; then
  echo -e "${CYAN}[*] Installing systemd service...${RESET}"
  sudo cp "$SERVICE_SRC" "$SERVICE_DST"
  sudo systemctl daemon-reload
fi

# Enable on boot
sudo systemctl enable "$SERVICE" --quiet 2>/dev/null

# Stop if already running (clean restart)
sudo systemctl stop "$SERVICE" 2>/dev/null || true

# Start
sudo systemctl start "$SERVICE"

sleep 1
if systemctl is-active --quiet "$SERVICE"; then
  # Get configured port
  PORT=$(python3 -c "
import sys; sys.path.insert(0, '$(dirname "$(readlink -f "$0")")')
from core.config import get_config
c = get_config()
print(c.get_int('web', 'port', fallback=8181))
" 2>/dev/null || echo 8181)

  HTTPS=$(python3 -c "
import sys; sys.path.insert(0, '$(dirname "$(readlink -f "$0")")')
from core.config import get_config
c = get_config()
print(c.get('web', 'https', fallback='true'))
" 2>/dev/null || echo true)

  if [ "$HTTPS" = "false" ]; then PROTO="http"; else PROTO="https"; fi

  # Get LAN IP
  IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  [ -z "$IP" ] && IP="localhost"

  echo -e "${GREEN}[+] AUTARCH Web Dashboard running${RESET}"
  echo -e "    ${PROTO}://${IP}:${PORT}"
  echo -e "    Logs: journalctl -u ${SERVICE} -f"
else
  echo -e "${RED}[X] Failed to start. Check: journalctl -u ${SERVICE} -e${RESET}"
  exit 1
fi
