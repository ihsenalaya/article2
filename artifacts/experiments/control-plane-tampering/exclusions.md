# Exclusions and discarded runs — Trust-boundary hardening (Task 11)

Per experiment protocol rule 21: failed/invalidated runs are never silently
deleted. This task's retained run (`raw/results.jsonl`, 10/10 records
matching expectations) was not preceded by any discarded automated run —
but two real issues were found and fixed along the way, documented here
rather than left implicit.

## Deployment-drift bug: applying Task 11's RBAC change silently reverted the running image

`deploy/azure/cpu-campaign-20260813/manifests/agent-daemonset.yaml`'s
`image:` field had never been updated past
`cpu-campaign-20260813-task06`, even though Task 10 changed the running
DaemonSet's image imperatively via `kubectl set image` (never updating
the source manifest to match). Applying this task's RBAC addition via
`kubectl apply -f agent-daemonset.yaml` re-applied the WHOLE manifest,
including that stale `image:` field — silently reverting the live
cluster back to the pre-Task-10 image (no BPF-LSM verifier fixes, no
Task 11 code at all) until caught by checking
`kubectl get ds ... -o jsonpath='{...image}'` immediately after and
finding it did not match what had just been built. Fixed by updating the
manifest's `image:` field to the newly-built `task11` tag before
re-applying — and, going forward, the manifest file is now the source of
truth again rather than having drifted from it. This is a real, generally
applicable lesson (imperative `kubectl set image` without updating the
source manifest is not durable across any later `kubectl apply` of that
same manifest), not specific to trust validation, but caught during this
task's own deployment step.

## Transient rejection during the "valid D + correct P" condition's first reconcile cycle

Observed once during interactive testing before the automated `n=5`
retained run: the FIRST reconcile cycle immediately after minting a
decision and patching its `AIPlacementDecision.Status.Decision` to
`"allow"` sometimes caught `status.decision=""` still (a real, momentary
propagation gap between the `kubectl patch --subresource=status` call
returning and that status actually being visible to the agent's next
`List()`), correctly logging a rejection for that one cycle before
converging to `ACCEPTED` on the next 5-second poll. This is NOT a bug —
it is the trust-validation code correctly treating a genuinely-ambiguous
transient state as untrusted rather than assuming the best case — but it
meant the retained run's `steady_state_verdict` helper needed to check
past the first reconcile cycle (see `scripts/lib.sh`) rather than
snapshotting the very first log line, to report the settled outcome
rather than a startup artifact. All 5 `valid_D_correct_P` reps in the
retained run show a clean, stable `ACCEPTED` verdict using this
steady-state check.

## What was NOT investigated further

- The `ReplayLedger`'s in-memory-only limitation (does not survive agent
  restarts) is stated as a known, honest limitation in
  `trustverify.go`'s doc comment and `experiment-config.json`, not
  exercised by a dedicated "agent restarts mid-replay-attempt" test in
  this task's time budget.
- Anti-rollback and forged-nonce-replay rejection are covered by unit
  tests (`ebpf-agent/internal/trustverify/trustverify_test.go`), not by
  a live cluster test in this experiment's `raw/` data — the live tests
  here focus on the two scenarios the experiment protocol explicitly asks for
  (valid D + correct P; valid D + tampered P), with the anti-replay
  ledger's own correctness covered at the unit level instead, which is
  faster and more precise for that specific property.

## Task 12 follow-up (2026-08-14): "agent restarts mid-replay-attempt" now covered live

The gap named above ("not exercised by a dedicated 'agent restarts
mid-replay-attempt' test") is now closed with a real live test, not just
the pre-existing unit tests: see `summary.md`'s "Task 12 follow-up"
section for the full account. A real decision was applied, the ledger
file's content was directly inspected on the node, the agent was
restarted on the same node, and a genuine replay attempt (same
epoch/version, different nonce) was correctly rejected post-restart
using the reloaded, persisted state — not a fresh, empty ledger. No raw
data file was added for this specific check (it was a manual,
single-shot verification rather than a repeated-n experiment, matching
the scale of the mechanism being verified — a boolean "does persistence
work at all" question, not a statistical one); the exact commands and
log output are recorded in `summary.md` and this session's own
`bpf-lsm`/`performance` follow-up sections for cross-reference.
