#!/bin/bash
# Runs INSIDE the kind node container (copied there by measure_hook_latency.sh
# via `docker cp`, invoked via `docker exec ... bash /tmp/hook_probe.sh`).
# Joins the target container's pid/net/uts/ipc namespaces (not mount, so the
# node's own strace/bash/coreutils stay reachable), moves itself into the
# container's real leaf cgroup (so the eBPF agent's cgroup-keyed policy
# lookup sees the same cgroup ID a real process in that pod would — see
# cgroupmap bug #11 in EXPERIMENTS_LOG.md), then runs an strace -c -f summary
# of a tight syscall loop for the requested hook.
set -uo pipefail

if [ "${1:-}" = "--inner" ]; then
  shift
  CGROUP_PROCS="$1"; HOOK="$2"; N="$3"; IP="$4"
  echo $$ > "$CGROUP_PROCS"
  case "$HOOK" in
    execve)
      strace -c -f bash -c "for i in \$(seq 1 $N); do /bin/true; done" 2>&1
      ;;
    openat)
      strace -c -f bash -c "for i in \$(seq 1 $N); do cat /etc/hostname > /root/hook-latency-out; done" 2>&1
      ;;
    connect)
      strace -c -f bash -c "for i in \$(seq 1 $N); do (exec 3<>/dev/tcp/$IP/80) 2>/dev/null; done" 2>&1
      ;;
  esac
  exit 0
fi

HOST_PID="$1"; CGROUP_PROCS="$2"; HOOK="$3"; N="$4"; IP="$5"
nsenter --target "$HOST_PID" --pid --net --uts --ipc -- "$0" --inner "$CGROUP_PROCS" "$HOOK" "$N" "$IP"
