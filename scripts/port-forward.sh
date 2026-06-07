#!/usr/bin/env bash
#
# Waits for WebGoat to be ready, then port-forwards it to localhost and keeps the
# tunnel alive (kubectl port-forward dies on pod restarts or idle timeouts, so we
# auto-reconnect). Ctrl-C to stop.
#
# Usage:
#   ./scripts/port-forward.sh
#
# Config via env:
#   APP_NS        default webgoat
#   WEBGOAT_PORT  default 8080   (local:remote both use this)
#   WEBWOLF_PORT  default 9090
#   WAIT_TIMEOUT  default 300s
#
set -uo pipefail

APP_NS="${APP_NS:-webgoat}"
WEBGOAT_PORT="${WEBGOAT_PORT:-8080}"
WEBWOLF_PORT="${WEBWOLF_PORT:-9090}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-300s}"

trap 'echo; echo "Stopped port-forwarding."; exit 0' INT TERM

echo "==> Waiting for a ready WebGoat pod (up to ${WAIT_TIMEOUT})"
if ! kubectl -n "$APP_NS" wait --for=condition=ready pod -l app=webgoat --timeout="$WAIT_TIMEOUT"; then
  echo "ERROR: WebGoat pod did not become ready in time." >&2
  exit 1
fi

echo "==> WebGoat is up. Forwarding:"
echo "      http://localhost:${WEBGOAT_PORT}/WebGoat   (WebGoat)"
echo "      http://localhost:${WEBWOLF_PORT}/WebWolf   (WebWolf)"
echo "    Ctrl-C to stop."
echo

# Keep the tunnel alive across drops.
while true; do
  kubectl -n "$APP_NS" port-forward svc/webgoat \
    "${WEBGOAT_PORT}:8080" "${WEBWOLF_PORT}:9090"
  echo "port-forward dropped; reconnecting in 2s... (Ctrl-C to stop)"
  sleep 2
done
