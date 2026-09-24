# Exclusions and discarded runs — Experiment D (Task 07)

Per experiment protocol rule 21: this file records discarded runs, if any. Unlike
Tasks 05/06, **no run was discarded in Task 07** — the single sweep of 10
repetitions (`raw/d1-pod-recreation.jsonl`) succeeded cleanly on the first
attempt, with no bugs found in the harness and no unexpected results.

This is stated explicitly, not silently omitted, for the same reason the
experiment protocol requires documenting negative/qualified results: an empty
exclusions file is itself a claim ("this ran cleanly the first time") that
should be visible and checkable, not just implied by the absence of a
`discarded-runs/` directory contents.

`discarded-runs/` exists as an empty directory for structural consistency
with the other experiment directories in this campaign, in case a future
rerun of this script does need to discard data.

## Design decisions made before running (not bugs, documented for context)

- **Pod A's decision/policy is deliberately not deleted alongside Pod A.**
  The protocol's exact framing ("Policy(A) MUST NOT become active for
  B") tests the *original* policy object against the recreated pod. A
  version of this experiment that also deleted/recreated the decision for
  Pod B would be testing something adjacent but different (whether a fresh
  authorization for B works correctly, which Task 06's experiments already
  exercise incidentally) rather than the specific stale-binding regression
  the experiment protocol asks about.
- **`applied_cgroups_unchanged` as the primary external signal**, rather
  than attempting to directly introspect the eBPF `cgroup_configs` map from
  outside the agent process (not straightforwardly possible without an
  agent-side debug endpoint, which does not exist and was not added for
  this task). `RuntimeSecurityPolicy.Status.appliedCgroupIDs` is only ever
  written by `markPolicyEnforcementReady`, itself only reachable after
  `reconcileOnce`'s UID-mismatch check passes — so this field changing is
  both necessary and sufficient evidence of a new bind having occurred,
  making it a faithful proxy for the internal state without needing
  privileged introspection.
