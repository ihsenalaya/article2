# Clean kind laboratory

This directory contains the reproducible local laboratory for TASK-02.

## Create

```sh
deploy/kind/create-lab.sh
```

The script:

- inventories current `kind`, `kubectl`, and Docker state;
- deletes only the project cluster named `article2` if it already exists;
- creates the cluster from `deploy/kind/kind-config.yaml`;
- builds and loads `runtime-guard-operator:dev` and `runtime-guard-ebpf-agent:dev`;
- applies the upstream `AIPlacementDecision` CRD, this project's CRDs, trust anchors, operator, and agent;
- runs `deploy/kind/validate-lab.sh`.

## Validate

```sh
deploy/kind/validate-lab.sh
```

Validation checks nodes, DNS, storage classes, CRDs, operator rollout, and agent rollout.

## Destroy

```sh
deploy/kind/destroy-lab.sh
```

The destroy script removes only the project cluster selected by `KIND_CLUSTER`, defaulting to `article2`.

## Overrides

```sh
KIND_CLUSTER=article2 KUBE_CONTEXT=kind-article2 deploy/kind/create-lab.sh
OPERATOR_IMAGE=runtime-guard-operator:dev AGENT_IMAGE=runtime-guard-ebpf-agent:dev deploy/kind/create-lab.sh
```

This is a local functional laboratory only. It does not prove confidential-computing, H100, or hardware attestation properties.
