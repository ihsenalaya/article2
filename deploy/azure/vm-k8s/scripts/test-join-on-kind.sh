#!/usr/bin/env bash
# UNVERIFIED DRAFT -- written 2026-08-09, NOT YET EXECUTED. Docker Desktop's
# WSL integration was unreachable from this shell at write time
# ("command 'docker' could not be found in this WSL 2 distro"), so this
# script has not been run even once. Read it, fix anything that's wrong
# empirically before trusting its output -- same discipline as
# setup-gpu-container-runtime.sh's own "UNVERIFIED DRAFT" header elsewhere
# in this repo.
#
# Purpose: dry-run bootstrap-worker.sh + join-worker.sh's actual kubeadm
# join mechanics against a REAL kubeadm control plane (kind's own -- kind
# nodes run kubeadm+systemd+containerd internally, so this is a real
# kubeadm join, not a simulation) before ever pointing the same scripts at
# a real, billed Azure VM. This is what the experiment protocol ("all scripts must
# first be prepared and validated locally using kind whenever technically
# possible") requires for the H100 join flow specifically.
#
# What this does NOT test: anything GPU/confidential-computing-specific
# (kind has no GPU, no SEV-SNP). Only the join mechanics: token retrieval,
# `kubeadm join` invocation, node registration, Ready wait, labeling. GPU
# checks are validate-gpu-worker.sh's job and can only run on real hardware.
#
# Approach: kind's own node containers (kindest/node image) already run
# systemd + containerd + kubeadm/kubelet as PID 1, the same init model as a
# real Ubuntu VM -- so a throwaway container built FROM THE SAME kindest/node
# image, attached to the kind docker network but NOT part of the kind
# cluster's own node list, is a much closer stand-in for a real VM than a
# bare `ubuntu` container (no systemd, would make bootstrap-worker.sh's
# `systemctl` calls fail for reasons that have nothing to do with the join
# logic being tested).
#
# Usage: ./test-join-on-kind.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIND_CLUSTER="${KIND_CLUSTER:-article2}"
DRYRUN_NAME="${DRYRUN_NAME:-h100-join-dryrun}"
DRYRUN_NODE_NAME="${DRYRUN_NODE_NAME:-h100-join-dryrun-node}"
SSH_KEY="${SSH_KEY:-${TMPDIR:-/tmp}/h100-join-dryrun-key}"

cleanup() {
  echo "=== cleanup: removing dry-run container ==="
  docker rm -f "$DRYRUN_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== 1/6: confirm kind cluster '$KIND_CLUSTER' exists (do not create/destroy here) ==="
if ! kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER"; then
  echo "kind cluster '$KIND_CLUSTER' not found. This script intentionally does not create" >&2
  echo "one -- reuse the project's own kind bring-up (deploy/kind/create-lab.sh) so this" >&2
  echo "dry-run exercises the same cluster the rest of the suite already validated." >&2
  exit 1
fi

CP_CONTAINER="${KIND_CLUSTER}-control-plane"
NODE_IMAGE="$(docker inspect -f '{{.Config.Image}}' "$CP_CONTAINER")"
echo "control-plane container: $CP_CONTAINER, node image: $NODE_IMAGE"

echo "=== 2/6: generate an ephemeral SSH key for this dry-run only ==="
mkdir -p "$(dirname "$SSH_KEY")"
rm -f "$SSH_KEY" "$SSH_KEY.pub"
ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -q

echo "=== 3/6: start a throwaway kindest/node container on the kind network (not a kind-managed node) ==="
# Publish sshd on an ephemeral host port instead of relying on the
# container's internal bridge IP (172.18.x.x): this WSL distro's network
# namespace has no route to the "kind" bridge network (that network lives
# inside Docker Desktop's own backend) -- confirmed empirically ("No route
# to host" on a direct-IP ssh attempt, 2026-08-09). Published ports on
# 127.0.0.1 ARE reachable from here, which is also how kind's own
# kubeconfig reaches the control plane's API server.
docker rm -f "$DRYRUN_NAME" >/dev/null 2>&1 || true
docker run -d --name "$DRYRUN_NAME" \
  --network "kind" \
  --privileged \
  --cgroupns=host \
  --tmpfs /tmp --tmpfs /run \
  -v /var \
  -p 127.0.0.1::22 \
  "$NODE_IMAGE" >/dev/null
DRYRUN_SSH_PORT="$(docker port "$DRYRUN_NAME" 22/tcp | head -1 | cut -d: -f2)"
echo "dry-run container SSH published at 127.0.0.1:$DRYRUN_SSH_PORT"

echo "=== 4/6: install sshd + inject the dry-run public key (kindest/node has no sshd by default) ==="
docker exec "$DRYRUN_NAME" bash -c "
  set -euo pipefail
  apt-get update -qq && apt-get install -y -qq openssh-server sudo >/dev/null
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  cat > /root/.ssh/authorized_keys <<'PUBKEY'
$(cat "$SSH_KEY.pub")
PUBKEY
  chmod 600 /root/.ssh/authorized_keys
  sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config || true
  service ssh start || /usr/sbin/sshd
"
echo "=== 5/6: run bootstrap-worker.sh against it (real kubeadm/kubelet install path, root@ instead of azureuser@) ==="
# kindest/node images already have containerd/kubeadm/kubelet baked in, so
# bootstrap-worker.sh's apt-get branch is expected to mostly no-op (its own
# idempotency check) -- this run is really validating that the script
# DETECTS that correctly rather than failing or double-installing.
SSH_PORT="$DRYRUN_SSH_PORT" "$SCRIPT_DIR/bootstrap-worker.sh" 127.0.0.1 root "$SSH_KEY"

echo "=== 6/6: real kubeadm join against kind's real control plane, no Terraform/Azure involved ==="
JOIN_COMMAND="$(docker exec "$CP_CONTAINER" kubeadm token create --print-join-command --ttl 10m)"
ssh -p "$DRYRUN_SSH_PORT" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -i "$SSH_KEY" "root@127.0.0.1" \
  "$JOIN_COMMAND --cri-socket unix:///run/containerd/containerd.sock --node-name $DRYRUN_NODE_NAME"

echo "=== verifying node registration on the REAL kind cluster ==="
for attempt in $(seq 1 30); do
  if kubectl --context "kind-${KIND_CLUSTER}" get "node/$DRYRUN_NODE_NAME" >/dev/null 2>&1; then
    break
  fi
  echo "  waiting for node object to register ($attempt/30)"
  sleep 5
done
kubectl --context "kind-${KIND_CLUSTER}" get "node/$DRYRUN_NODE_NAME" -o wide
kubectl --context "kind-${KIND_CLUSTER}" wait --for=condition=Ready "node/$DRYRUN_NODE_NAME" --timeout=120s
kubectl --context "kind-${KIND_CLUSTER}" label node "$DRYRUN_NODE_NAME" dryrun=h100-join-test --overwrite

echo "=== draining and removing the dry-run node from the kind cluster (cleanup, do not leave it registered) ==="
kubectl --context "kind-${KIND_CLUSTER}" delete "node/$DRYRUN_NODE_NAME" --ignore-not-found

echo "PASS: join-worker.sh's underlying kubeadm join mechanics work against a real kubeadm control plane."
echo "(container cleanup runs via trap on exit)"
