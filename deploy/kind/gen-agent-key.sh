#!/usr/bin/env bash
# Generates a fresh Ed25519 key pair for the node eBPF agent to sign
# RuntimePlacementEvidence with, and stores the private half in a Secret the
# DaemonSet mounts (AGENT_SIGNING_KEY_HEX). This is a distinct keypair from
# the trust-anchor one (gen-trust-anchor.sh) — that one belongs to article
# 1's scheduler (verified by the Operator); this one belongs to the agent
# itself (used to sign evidence, verified by whoever consumes
# RuntimePlacementEvidence — not implemented as a separate verifier in this
# phase, but the public half is printed here for that future use).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPERATOR_DIR="$(cd "$SCRIPT_DIR/../../operator" && pwd)"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-article2}"
NAMESPACE="${AGENT_NAMESPACE:-runtime-guard-agent-system}"
SECRET_NAME="${AGENT_SECRET_NAME:-runtime-guard-agent-signing-key}"

echo "Generating fresh Ed25519 agent signing key pair..."
KEYS_OUTPUT="$(cd "$OPERATOR_DIR" && go run ./cmd/gen-keypair)"
PUBLIC_KEY_HEX="$(echo "$KEYS_OUTPUT" | grep '^PUBLIC_KEY_HEX=' | cut -d= -f2)"
PRIVATE_KEY_HEX="$(echo "$KEYS_OUTPUT" | grep '^PRIVATE_KEY_HEX=' | cut -d= -f2)"

if [[ -z "$PUBLIC_KEY_HEX" || -z "$PRIVATE_KEY_HEX" ]]; then
  echo "failed to generate key pair" >&2
  exit 1
fi

kubectl --context "$KUBE_CONTEXT" create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT" apply -f -
kubectl --context "$KUBE_CONTEXT" create secret generic "$SECRET_NAME" \
  --namespace "$NAMESPACE" \
  --from-literal="privateKeyHex=$PRIVATE_KEY_HEX" \
  --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT" apply -f -

echo "Agent signing key Secret '$SECRET_NAME' applied to namespace '$NAMESPACE'."
echo "Public key (for future evidence verifiers): $PUBLIC_KEY_HEX"
