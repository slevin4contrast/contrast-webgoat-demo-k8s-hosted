#!/usr/bin/env bash
#
# Removes the demo. Safe to run on a shared cluster -- only deletes what setup.sh
# created.
#
# Usage:
#   ./scripts/teardown.sh          # remove WebGoat + operator release
#   ./scripts/teardown.sh --crds   # also delete the Contrast CRDs (cluster-wide)
#   KIND=1 ./scripts/teardown.sh   # delete the throwaway kind cluster instead
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

[[ -f .env ]] && { set -a; source .env; set +a; }
KIND="${KIND:-0}"
CLUSTER_NAME="contrast-webgoat"
OPERATOR_NS="contrast-agent-operator"
APP_NS="webgoat"
DELETE_CRDS=0
[[ "${1:-}" == "--crds" ]] && DELETE_CRDS=1

# Clear the Contrast UI first so re-running the demo starts fresh. This is a
# Contrast-side API call (independent of the cluster), so it runs for both the kind and
# kubeadm paths. It no-ops if API credentials aren't set. Disable with CLEAR_UI=0.
# By default it clears findings only (issues mode, needs just the Edit role). To delete
# the whole application (app + libraries + route coverage), set CONTRAST_CLEAR_MODE=app
# -- that requires an Admin-role Authorization header.
CLEAR_UI="${CLEAR_UI:-1}"
if [[ "$CLEAR_UI" == "1" ]]; then
  # Prefer Homebrew node (18+) for global fetch support, fall back to PATH node.
  NODE_BIN=""
  if [[ -x /opt/homebrew/bin/node ]]; then
    NODE_BIN=/opt/homebrew/bin/node
  elif command -v node >/dev/null 2>&1; then
    NODE_BIN=node
  fi
  if [[ -n "$NODE_BIN" ]]; then
    echo "==> Clearing Contrast UI (so the next run is fresh)"
    "$NODE_BIN" "$SCRIPT_DIR/clear-contrast-ui.mjs" || echo "   (UI clear skipped/failed; continuing teardown)"
  else
    echo "==> Skipping Contrast UI clear (node not found on PATH)"
  fi
fi

if [[ "$KIND" == "1" ]]; then
  echo "==> Deleting kind cluster '$CLUSTER_NAME'"
  kind delete cluster --name "$CLUSTER_NAME"
  echo "Done."
  exit 0
fi

echo "==> Removing WebGoat namespace"
# Delete the AgentInjector effect first by removing the labeled workload, then ns.
kubectl delete -f manifests/10-webgoat.yaml --ignore-not-found
kubectl delete -f manifests/00-namespace.yaml --ignore-not-found

echo "==> Uninstalling Contrast Agent Operator Helm release"
helm uninstall contrast-agent-operator --namespace "$OPERATOR_NS" || true
kubectl delete namespace "$OPERATOR_NS" --ignore-not-found

if [[ "$DELETE_CRDS" == "1" ]]; then
  echo "==> Deleting Contrast CRDs (cluster-wide)"
  kubectl get crd -o name | grep 'contrastsecurity.com' | xargs -r kubectl delete
fi

echo "Done."
