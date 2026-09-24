# Discarded runs (Experiment E, Task 08)

Contents of this directory, and why they are not part of the reported E1-E4 results:

- `canary1-*`, `debug1-*`, `debugrep*-*`, `diag1-*`, `sleepfix1-*`, `smoketest*-*`,
  `tickcheck-*`, `verify*-*`, `waitloop-*`, `final*-*`: manual smoke-test /
  debug invocations of `scale-generator` made while diagnosing the
  `imagePullPolicy` stale-image bug and the watch-vs-poll investigation
  (see TASK_08_REVIEW.md / summary.md). Not part of any experiment sweep,
  not independent reps of a defined condition.
- `e1-n1-rep1-26480.json`, `e1-n1-rep2-11987.json` (missing -- crashed before
  capture, see below), `e1-n1-rep3-24043.json`, `e1-n10-rep1-22586.json`,
  `e1-n10-rep2-26510.json`, `e1-n10-rep3-15745.json`, `e1-n50-rep1-22772.json`,
  `e1-steady-state-partial-run1.jsonl`: first attempt at the E1 steady-state
  sweep (run 1). Discarded in full and re-run from scratch because:
  1. N=1 rep=2 crashed the analysis step on a null `metrics_samples` field
     (a legitimate fast-convergence case, not a generator bug -- fixed in
     `run-e1.sh` by treating `null` as `[]`).
  2. That fix was applied to `run-e1.sh` on disk while the sweep was still
     running in the background, so reps after the fix (N=10, N=50 rep1) ran
     under an inconsistent mix of old/new analysis code.
  3. N=50 rep=1 then hit a `JSONDecodeError` (empty captured log). Direct
     cluster inspection at the time (`kubectl get pods -l experiment=scale`)
     showed 1 Completed + 50 Running pods with zero Pending -- ruling out a
     genuine scheduling/capacity failure at N=50 and pointing to a race in
     `run_scale_job` (job `succeeded=1` observed before the pod's log stream
     was fully retrievable via the API server). Fixed in `lib.sh` with a
     bounded retry-with-backoff on log capture, validating the captured
     text is non-empty and JSON-parseable before accepting it.

None of the values in these files are used in `processed/` or reported in
`summary.md`. They are retained here, not deleted, per the campaign's
no-silent-drop convention.
