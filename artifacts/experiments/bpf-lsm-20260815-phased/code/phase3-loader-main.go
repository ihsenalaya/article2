// Phase 3 minimal BPF-LSM map-driven test loader — standalone, same
// independence guarantee as phase 2's main.go.
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

type pathKey struct {
	Path [32]byte
}

func mustKey(s string) pathKey {
	var k pathKey
	copy(k.Path[:], s)
	return k
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("minimal_map.bpf.o")
	if err != nil {
		log.Fatalf("load collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("new collection (verifier rejection?): %v", err)
	}
	defer coll.Close()

	decisions := coll.Maps["decisions"]
	allowKey := mustKey("/tmp/runtimeguard-allow-target")
	denyKey := mustKey("/tmp/runtimeguard-deny-target")
	if err := decisions.Put(&allowKey, uint8(1)); err != nil {
		log.Fatalf("put allow entry: %v", err)
	}
	if err := decisions.Put(&denyKey, uint8(0)); err != nil {
		log.Fatalf("put deny entry: %v", err)
	}
	fmt.Println("MAP POPULATED")

	dumpMap := func() {
		var k pathKey
		var v uint8
		iter := decisions.Iterate()
		for iter.Next(&k, &v) {
			end := 0
			for end < len(k.Path) && k.Path[end] != 0 {
				end++
			}
			fmt.Printf("decisions[%q] = %d\n", string(k.Path[:end]), v)
		}
		if err := iter.Err(); err != nil {
			fmt.Printf("map iterate error: %v\n", err)
		}
	}
	dumpMap()

	prog := coll.Programs["map_lsm_exec"]
	if prog == nil {
		log.Fatalf("program map_lsm_exec not found in collection")
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		log.Fatalf("attach lsm/bprm_check_security: %v", err)
	}
	defer l.Close()
	fmt.Println("ATTACHED")

	countersMap := coll.Maps["counters"]
	dumpCounters := func() {
		labels := []string{"hook_entered", "deny_decisions", "allow_decisions_mapped", "allow_decisions_default"}
		for i := uint32(0); i < 4; i++ {
			var v uint64
			if err := countersMap.Lookup(&i, &v); err != nil {
				fmt.Printf("counters[%d=%s] lookup err: %v\n", i, labels[i], err)
				continue
			}
			fmt.Printf("counters[%d=%s]=%d\n", i, labels[i], v)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2)
	for s := range sig {
		if s == syscall.SIGUSR1 {
			dumpCounters()
			continue
		}
		if s == syscall.SIGUSR2 {
			dumpMap()
			continue
		}
		break
	}
	dumpCounters()
	fmt.Println("DETACHING")
}
