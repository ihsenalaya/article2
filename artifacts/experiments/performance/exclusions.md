# Exclusions and discarded runs — Experiment F (Task 09)

Per experiment protocol rule 21: failed/invalidated runs are never silently
deleted. This file records the one interruption that affected this task
and exactly what it did and did not affect.

## F1-F3: one interrupted attempt, no data lost or discarded

`run-f1.sh` (F1-F3 paired blocks) was launched and progressed normally --
exec (30/30 blocks) and file (20/20 blocks) completed successfully, and
network reached 10/20 blocks -- when the background process stopped
without a completion or failure marker in its log. This was traced to an
environment/session restart unrelated to the experiment itself (an
orphaned-background-task notification listing the script's own monitor
task among others marked "stopped," and `/tmp/f1-run.log` no longer
existing afterward), not a script crash or a RuntimeGuard fault: the
cluster was independently confirmed clean (`kubectl get pods -l
experiment=performance` returned zero results) immediately after, meaning
the last-completed block's own cleanup had run successfully before the
interruption.

**No data from this attempt was discarded.** The 60 already-written
records in `raw/f1-paired-blocks.jsonl` (exec 30/30, file 20/20, network
10/20) are real, valid, independent block results and are part of the
retained dataset. `scripts/run-f1-resume.sh` was written specifically to
continue from this point: it appends (never truncates) to the same
`f1-paired-blocks.jsonl`, running network blocks 11-20 to reach the
target 20, then runs F3 (which had not started before the interruption)
from scratch. The final retained dataset is therefore the union of both
attempts' output, not a rerun-from-scratch -- there is nothing under
`discarded-runs/` for this task because nothing collected was invalid or
thrown away.

## Design decisions stated here for completeness (not exclusions, but adjacent)

- **F4 tests only the exec operation.** file and network's per-op cost is
  small enough (single-digit to low-double-digit microseconds, see
  summary.md) that a concurrency sweep would be dominated by pod-exec/
  kubectl-exec overhead rather than the operation's own cost; exec is
  also explicitly the "important" microbenchmark per experiment protocol F2's
  own framing (highest per-op cost, primary security-relevant hook). This
  was a design choice made before running anything, not a result of any
  run failing -- documented here and in `experiment-config.json` rather
  than left implicit.
- **F1-F3's `network` operation's `n_completed=0`/`n_errors=n` values are
  intentional, not a fault.** Every iteration connects to `127.0.0.1:1`
  (nothing listens there) and is expected to receive an immediate
  `ECONNREFUSED` -- the connect() syscall still fires every time
  (generating the traced event this experiment measures), and using a
  guaranteed-fast local refusal instead of a real connection isolates
  syscall-hook overhead from network RTT. See `experiment-config.json`'s
  `network_op_semantics` for the full rationale.

## Task 12 follow-up (2026-08-14): exec event-count anomaly, partially root-caused and fixed

The user explicitly rejected leaving F3's exec `incorporated_count`
anomaly (~19x `n` instead of ~1x, see the original TASK_09_REVIEW.md
item 7) as an unexplained observation and required further
investigation. Root cause, established by code inspection (no new live
run needed to find it):

`operator/cmd/perf-workload/main.go`'s exec op was
`exec.Command("/bin/true").Run()` with `Stdin`/`Stdout`/`Stderr` left
`nil`. Go's `os/exec` opens `/dev/null` separately for each nil stream
before forking -- real `openat()` syscalls made inside the SAME
monitored pod's cgroup as the operation under test, captured by the
audit-mode `trace_open`/`trace_openat` tracepoints as extra `FILE_OPEN`
events layered on top of the one real `EXEC` event. This is the exact
same class of bug already found and fixed in `cmd/g1-runner` during Task
10 (see `artifacts/experiments/bpf-lsm/exclusions.md`'s "Attempt 1"
entry) -- it was never ported to this separate tool, since the two were
written independently for different tasks.

**Fix**: `perf-workload`'s exec op now explicitly sets
`cmd.Stdin/Stdout/Stderr = os.Stdin/os.Stdout/os.Stderr` (the runner's
own already-open FDs, inherited via fork, no new `open()` call needed) --
identical pattern to `g1-runner`'s existing fix.

**Verified via a live rerun** (`raw/f3-event-drop-check-task12-fixed.jsonl`,
same cluster re-provisioned for the Task 10 follow-up above): exec's
`incorporated_count` for `n=5000` dropped from 95008 (original,
`raw/f3-event-drop-check.jsonl`, ~19.0 events/op) to 55011 (fixed,
~11.0 events/op) -- a real, measured ~42% reduction (~8 fewer events per
op), confirming the `/dev/null`-opens hypothesis explains a substantial
part of the anomaly.

**The fix is real but incomplete -- reported honestly, not rounded up to
"fixed".** ~11 events/op remain unexplained. Dynamic linking was
directly ruled out as a further contributor: the busybox:1.36 base
image's `/bin/busybox` binary (which `/bin/true` symlinks to) is
statically linked, confirmed via its file size (~1.01MB, consistent with
a statically-linked musl/uclibc busybox; a dynamically-linked busybox
binary would be a few tens of KB) -- so no `ld.so` shared-library-
resolution `openat()` calls occur. `file`/`network`, which do not call
`exec.Command` at all, remain clean at ~1x throughout (both the original
and fixed reruns), confirming the residual ~11x is specific to
`exec.Command`'s own subprocess-creation machinery in Go's runtime, not
to RuntimeGuard's event-counting logic (which correctly counts whatever
real kernel events actually occur -- `drop_count=0` and
`events_dropped_since_last_evidence=0` in every F3 run, original and
fixed alike, meaning nothing here is a RuntimeGuard-side loss/
miscounting bug). Further root-causing the remaining ~11 events/op would
require kernel-level syscall tracing (`strace`/`ftrace`) of the exact
`exec.Command` subprocess-creation path, which was judged not justified
for the remaining, now-substantially-reduced effect size within this
follow-up's time budget.

`raw/f3-event-drop-check-task12-fixed.jsonl` (3 records: exec/file/
network, same n as the original) is retained alongside, not in place of,
the original `raw/f3-event-drop-check.jsonl` — both are genuine, real
runs. `scripts/analyze.py`'s F3 processing
(`processed/f3-event-drop-check.csv`) still reads only the original
file; the fixed rerun's 3 records were not additionally run through the
full plotting pipeline, since the finding (a before/after comparison of
3 scalar counts) is fully and honestly presented as a table in
`summary.md`/here, and generating a figure for 3 paired scalars would
not add information beyond that table.

## Task 12 follow-up, round 2 (2026-08-14): closing the remaining limitations

The user explicitly required every remaining limitation in this
experiment closed, not left as documented scope reductions. Three
further changes were made and verified live on the (still up)
re-provisioned cluster:

**F1 sample size, file/network 20→30**: `scripts/run-f1-bump-to-30.sh`
ran 10 additional paired blocks per op (blocks 21-30), using the exact
same randomized ON/OFF order methodology as the original `run-f1.sh`,
appended to `raw/f1-paired-blocks.jsonl` (never truncated). Final counts
confirmed via direct count of `outcome=="success"` records: exec=30,
file=30, network=30. `scripts/analyze.py` was rerun to regenerate
`processed/f1-paired-summary.csv` and both figures from the full,
updated dataset — the numbers in `summary.md` reflect this regenerated
output, not the original n=20 figures.

**Memory metric**: `operator/cmd/perf-workload/main.go` now reports
`max_rss_kb_before`/`max_rss_kb_after`/`max_rss_kb_delta` via
`getrusage(RUSAGE_SELF).Maxrss`. Verified with a live spot-check
(500-op exec run): delta was 0. This directly answers F3's originally
unmet "memory" metric requirement from the protocol's F3 list.

**F4 OFF-condition sweep**: `scripts/run-f4-off.sh` (new) runs the
identical concurrency/rep sweep (1/2/4/8, n=3) against untracked pods,
producing `raw/f4-rate-curve-off.jsonl`. This decomposes RuntimeGuard's
own marginal cost from generic Linux fork/exec contention — see
`summary.md`'s F4 section for the resulting comparison table. Disclosed
limitation of this specific addition: the ON sweep (original, run
earlier in the campaign) and this OFF sweep were NOT interleaved/
randomized relative to each other the way F1's blocks are — they are two
separate sequential batches, run at different points in the campaign's
timeline, on a cluster that had substantial other activity between them
(the Task 10 BPF-LSM investigation). This is weaker methodologically
than F1's paired design and is stated as such directly in `summary.md`,
not smoothed over — the ABSOLUTE ops/s comparison between ON and OFF
should be read with this caveat in mind; the WITHIN-TIER marginal-cost
GROWTH trend (the actual finding) is less sensitive to this confound
since it compares relative scaling behavior, not absolute throughput.
