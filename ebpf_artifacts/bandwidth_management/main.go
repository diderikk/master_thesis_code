package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event program program.bpf.c

import (
	"log"
	"math"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
)

func main() {

	var ebpfObjects = LoadObjects(&ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  math.MaxUint32 >> 2,
		},
	})

	go asyncResetCounter[programIpv4Key](*ebpfObjects.PktCount)

	attachEbpf(ebpfObjects)
}

// Continously reset eBPF map counting packets between to pods
func asyncResetCounter[T programIpv4Key](programMap ebpf.Map) {
	log.Println("Resetting begun...")

	tick := time.Tick(10 * time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			it := programMap.Iterate()
			var keys []T
			for {
				var key T
				var value uint64
				isMoreEntries := it.Next(&key, &value)

				if isMoreEntries {
					keys = append(keys, key)
				} else {
					break
				}
			}

			deleted, err := programMap.BatchDelete(keys, &ebpf.BatchOptions{})
			if err != nil {
				log.Fatal("Map batch delete:", err)
			} else {
				log.Println("Number of deleted keys: ", deleted)
			}

		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
