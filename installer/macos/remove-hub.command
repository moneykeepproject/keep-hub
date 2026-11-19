#!/bin/bash
# Stop this Mac being the household's Keep Hub. Its data (the hub's name, the household's
# members and paired phones) stays in ~/Library/Application Support/Keep Hub, so installing
# it again carries on. Asks for your password once, only to remove launchd's file for the hub:
# nothing of Keep Hub's runs as root. (Adapted from ShareKeep's uninstall-hub.command.)
set -euo pipefail
HUB="/Applications/Keep Hub.app/Contents/MacOS/keep-hub"
DATA="$HOME/Library/Application Support/Keep Hub"
LABEL="org.moneykeep.keep-hub"
if [ -x "$HUB" ] && [ -f "$DATA/hub.json" ]; then
  APPS="$("$HUB" registered-apps --data "$DATA" || true)"
  if [ -n "$APPS" ]; then
    echo "These apps still use Keep Hub: $APPS."
    echo "Their phones will stop connecting."
    read -r -p "Remove Keep Hub anyway? [y/N] " ANSWER
    case "$ANSWER" in
      y|Y|yes|Yes) ;;
      *) echo "Keep Hub stays."; read -r -p "Press Return to close." _; exit 0 ;;
    esac
  fi
fi
sudo /bin/launchctl bootout "system/$LABEL" 2>/dev/null || true
sudo /bin/rm -f "/Library/LaunchDaemons/$LABEL.plist"
echo "Keep Hub is stopped. Its data is still in ~/Library/Application Support/Keep Hub;"
echo "delete that folder yourself only if you won't use Keep Hub again."
read -r -p "Press Return to close." _
