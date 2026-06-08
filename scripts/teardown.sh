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
#
# LIBRARY SAFETY: the default 'issues' mode clears vulns/attacks/incidents/routes but
# KEEPS libraries and CVE/SCA. The 'reset' and 'app' modes PURGE libraries. To prevent
# losing library data by accident, teardown downgrades reset/app to 'issues' unless you
# explicitly set CLEAR_ALLOW_LIBRARY_LOSS=1.
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
    CLEAR_MODE_EFF="$(printf '%s' "${CONTRAST_CLEAR_MODE:-issues}" | tr '[:upper:]' '[:lower:]')"
    MODE_ARG=()
    if [[ "$CLEAR_MODE_EFF" == "reset" || "$CLEAR_MODE_EFF" == "app" ]]; then
      if [[ "${CLEAR_ALLOW_LIBRARY_LOSS:-0}" == "1" ]]; then
        echo "==> WARNING: CONTRAST_CLEAR_MODE=$CLEAR_MODE_EFF will PURGE library/CVE data (allowed via CLEAR_ALLOW_LIBRARY_LOSS=1)"
      else
        echo "==> NOTE: CONTRAST_CLEAR_MODE=$CLEAR_MODE_EFF would purge libraries; downgrading to 'issues' to protect library/CVE data"
        echo "          (set CLEAR_ALLOW_LIBRARY_LOSS=1 if you really want the full reset/delete)"
        MODE_ARG=(--mode issues)
      fi
    fi
    echo "==> Clearing Contrast UI (so the next run is fresh; libraries preserved)"
    if [[ ${#MODE_ARG[@]} -gt 0 ]]; then
      "$NODE_BIN" "$SCRIPT_DIR/clear-contrast-ui.mjs" "${MODE_ARG[@]}" || echo "   (UI clear skipped/failed; continuing teardown)"
    else
      "$NODE_BIN" "$SCRIPT_DIR/clear-contrast-ui.mjs" || echo "   (UI clear skipped/failed; continuing teardown)"
    fi
  else
    echo "==> Skipping Contrast UI clear (node not found on PATH)"
  fi
fi

# Stop the auto-reconnecting port-forward (started by setup.sh). Best-effort: kills the
# wrapper script and the kubectl tunnel for the webgoat service. Called as the LAST step.
stop_port_forward() {
  echo "==> Stopping port-forward"
  pkill -f "scripts/port-forward.sh" 2>/dev/null || true
  pkill -f "port-forward svc/webgoat" 2>/dev/null || true
}

if [[ "$KIND" == "1" ]]; then
  echo "==> Deleting kind cluster '$CLUSTER_NAME'"
  kind delete cluster --name "$CLUSTER_NAME"
else
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
fi

# Final step: end port-forwarding.
stop_port_forward

echo "Done."
