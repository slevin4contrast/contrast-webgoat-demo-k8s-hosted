#!/usr/bin/env bash
#
# Quick health check for the demo. Run before a live walkthrough.
#
set -uo pipefail
OPERATOR_NS="contrast-agent-operator"
APP_NS="webgoat"

echo "===== Operator ====="
kubectl -n "$OPERATOR_NS" get pods 2>/dev/null || echo "  operator namespace not found"

echo
echo "===== WebGoat ====="
kubectl -n "$APP_NS" get pods 2>/dev/null || echo "  webgoat namespace not found"

echo
echo "===== Injectors targeting webgoat ====="
kubectl -n "$APP_NS" get agentinjector 2>/dev/null || echo "  (injectors are ClusterAgentInjectors; checking operator ns)"
kubectl -n "$OPERATOR_NS" get clusteragentinjector 2>/dev/null

echo
echo "===== Agent instrumentation check ====="
if kubectl -n "$APP_NS" get deploy/webgoat >/dev/null 2>&1; then
  echo "Looking for the Contrast init container + javaagent line..."
  kubectl -n "$APP_NS" get pod -l app=webgoat -o jsonpath='{range .items[*].spec.initContainers[*]}initContainer: {.name}{"\n"}{end}' 2>/dev/null
  kubectl -n "$APP_NS" logs deploy/webgoat 2>/dev/null | grep -i -m3 contrast || echo "  no Contrast log lines yet (give it a minute after first start)"
else
  echo "  webgoat deployment not found"
fi
