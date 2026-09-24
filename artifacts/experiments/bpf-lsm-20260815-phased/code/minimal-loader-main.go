// Phase 2 minimal BPF-LSM test loader — standalone, no dependency on
// RuntimeGuard's own ebpf-agent code (only the same third-party cilium/ebpf
// library RuntimeGuard also happens to use).
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("minimal.bpf.o")
	if err != nil {
		log.Fatalf("load collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("new collection (verifier rejection?): %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["minimal_lsm_exec"]
	if prog == nil {
		log.Fatalf("program minimal_lsm_exec not found in collection")
	}

	l, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		log.Fatalf("attach lsm/bprm_check_security: %v", err)
	}
	defer l.Close()

	fmt.Println("ATTACHED")

	countersMap := coll.Maps["counters"]
	dumpCounters := func() {
		labels := []string{"hook_entered", "deny_decisions", "allow_decisions"}
		for i := uint32(0); i < 3; i++ {
			var v uint64
			if err := countersMap.Lookup(&i, &v); err != nil {
				fmt.Printf("counters[%d=%s] lookup err: %v\n", i, labels[i], err)
				continue
			}
			fmt.Printf("counters[%d=%s]=%d\n", i, labels[i], v)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
	for s := range sig {
		if s == syscall.SIGUSR1 {
			dumpCounters()
			continue
		}
		break
	}
	dumpCounters()
	fmt.Println("DETACHING")
}
