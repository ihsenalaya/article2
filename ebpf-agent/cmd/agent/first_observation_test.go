package main

import (
	"testing"

	"github.com/ihsenalaya/runtime-guard-ebpf-agent/internal/bpfobjs"
)

func TestAccumulator_FirstObservationNotifiesOnlyOncePerCgroupUntilReset(t *testing.T) {
	acc := newAccumulator()

	acc.handle(bpfobjs.AgentEvent{CgroupId: 101, TimestampNs: 1000, Type: 1, Decision: 0})
	select {
	case obs := <-acc.firstObserved:
		if obs.cgroupID != 101 || obs.timestampNs != 1000 {
			t.Fatalf("unexpected first observation: %+v", obs)
		}
	default:
		t.Fatal("expected a first-observation notification for the first event on a fresh cgroup")
	}

	// A second event on the same cgroup must NOT produce another notification:
	// t_c is defined as the FIRST observed operation.
	acc.handle(bpfobjs.AgentEvent{CgroupId: 101, TimestampNs: 2000, Type: 1, Decision: 0})
	select {
	case obs := <-acc.firstObserved:
		t.Fatalf("unexpected second first-observation notification: %+v", obs)
	default:
	}

	// After resetFirstEvent (simulating a new policy generation being
	// applied), the next event must notify again.
	acc.resetFirstEvent([]uint64{101})
	acc.handle(bpfobjs.AgentEvent{CgroupId: 101, TimestampNs: 3000, Type: 1, Decision: 0})
	select {
	case obs := <-acc.firstObserved:
		if obs.timestampNs != 3000 {
			t.Fatalf("expected the post-reset event's timestamp 3000, got %d", obs.timestampNs)
		}
	default:
		t.Fatal("expected a fresh first-observation notification after resetFirstEvent")
	}
}

func TestAccumulator_ForgetAllClearsFirstSeenTracking(t *testing.T) {
	acc := newAccumulator()

	acc.handle(bpfobjs.AgentEvent{CgroupId: 202, TimestampNs: 500, Type: 2, Decision: 0})
	<-acc.firstObserved // drain the notification from the first event

	acc.forgetAll([]uint64{202})

	// forgetAll must also forget first-seen tracking (not just counters):
	// a cgroup ID reused by a later, unrelated pod must not inherit a stale
	// "already seen" state that would silently suppress its own real t_c.
	acc.handle(bpfobjs.AgentEvent{CgroupId: 202, TimestampNs: 999, Type: 2, Decision: 0})
	select {
	case obs := <-acc.firstObserved:
		if obs.timestampNs != 999 {
			t.Fatalf("expected timestamp 999 after forgetAll, got %d", obs.timestampNs)
		}
	default:
		t.Fatal("expected a first-observation notification after forgetAll reset first-seen tracking")
	}
}
