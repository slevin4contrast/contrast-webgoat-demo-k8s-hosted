#!/usr/bin/env bash
#
# One-command setup for the Contrast + WebGoat IAST demo.
#
#   1. (optional) creates a throwaway kind cluster
#   2. installs the Contrast Agent Operator via Helm, scoped to the webgoat namespace
#   3. deploys WebGoat with the contrast-agent=java label so it gets instrumented
#
# Usage:
#   cp .env.example .env   # then paste your CONTRAST_TOKEN
#   ./scripts/setup.sh
#
set -euo pipefail

# --- locate repo root and load .env -----------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; source .env; set +a
else
  echo "ERROR: .env not found. Run: cp .env.example .env  and fill in CONTRAST_TOKEN" >&2
  exit 1
fi

KIND="${KIND:-0}"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
CLUSTER_NAME="contrast-webgoat"
OPERATOR_NS="contrast-agent-operator"
APP_NS="webgoat"

# --- preflight ---------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' is not installed or not on PATH." >&2; exit 1; }; }
need kubectl
need helm
if [[ "$KIND" == "1" ]]; then need kind; fi

if [[ -z "${CONTRAST_TOKEN:-}" ]]; then
  echo "ERROR: CONTRAST_TOKEN is empty. Edit .env and paste your Contrast Agent Token." >&2
  exit 1
fi

# --- cluster selection -------------------------------------------------------
if [[ "$KIND" == "1" ]]; then
  if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    echo "==> Creating kind cluster '$CLUSTER_NAME'"
    kind create cluster --name "$CLUSTER_NAME" --config kind-cluster.yaml
  else
    echo "==> kind cluster '$CLUSTER_NAME' already exists"
  fi
  kubectl config use-context "kind-${CLUSTER_NAME}"
else
  if [[ -n "$KUBE_CONTEXT" ]]; then
    echo "==> Using kube context: $KUBE_CONTEXT"
    kubectl config use-context "$KUBE_CONTEXT"
  fi
  echo "==> Deploying into current context: $(kubectl config current-context)"
  echo "    (other namespaces are NOT touched -- injection is scoped to '$APP_NS')"
fi

# --- install / upgrade the Contrast Agent Operator via Helm ------------------
echo "==> Adding Contrast Helm repo"
helm repo add contrast https://contrastsecurity.dev/helm-charts >/dev/null 2>&1 || true
helm repo update contrast >/dev/null

echo "==> Installing Contrast Agent Operator (Helm)"
helm upgrade --install \
  --namespace "$OPERATOR_NS" --create-namespace \
  -f helm/contrast-agent-operator.values.yaml \
  --set clusterDefaults.tokenValue="$CONTRAST_TOKEN" \
  contrast-agent-operator contrast/contrast-agent-operator

echo "==> Waiting for the operator to become ready"
kubectl -n "$OPERATOR_NS" rollout status deployment/contrast-agent-operator --timeout=180s

# --- deploy WebGoat ----------------------------------------------------------
echo "==> Deploying WebGoat"
kubectl apply -f manifests/00-namespace.yaml

echo "==> Deploying networked HSQLDB (so DB traffic uses a TCP socket)"
kubectl apply -f manifests/05-webgoat-db.yaml
kubectl -n "$APP_NS" rollout status deployment/webgoat-db --timeout=180s

kubectl apply -f manifests/10-webgoat.yaml

echo "==> Waiting for WebGoat to start (this also waits on agent injection)"
kubectl -n "$APP_NS" rollout status deployment/webgoat --timeout=300s

cat <<EOF

============================================================
 Setup complete.

 Confirm the agent is instrumenting:
   kubectl -n $APP_NS logs deployment/webgoat | grep -i contrast

 Check status any time:
   ./scripts/status.sh

 Tear everything down:
   ./scripts/teardown.sh
============================================================
EOF

# Auto-start port-forwarding so WebGoat is reachable as soon as it's online.
# Set PORT_FORWARD=0 to skip (e.g. in CI / non-interactive runs).
PORT_FORWARD="${PORT_FORWARD:-1}"
if [[ "$PORT_FORWARD" == "1" ]]; then
  echo "==> Starting port-forward (Ctrl-C to stop; re-run ./scripts/port-forward.sh anytime)"
  exec "$SCRIPT_DIR/port-forward.sh"
else
  echo "Port-forward skipped (PORT_FORWARD=0). Start it with: ./scripts/port-forward.sh"
fi
