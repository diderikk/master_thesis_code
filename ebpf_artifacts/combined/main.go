package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event program  program.bpf.c

import (
	"log"
	"math"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

type ServiceMap struct {
	sync.RWMutex
	m map[string]Service
}

type EBPFMapOfMaps struct {
	sync.RWMutex
	m map[programKey]*ebpf.Map
}

type NetworkPolicyMap struct {
	sync.RWMutex
	m map[string]NetworkPolicy
}

type PodMap struct {
	sync.RWMutex
	m map[string][]Pod
}

type NamespaceMap struct {
	sync.RWMutex
	m map[string][]string
}

func main() {
	// https://pkg.go.dev/github.com/cilium/ebpf#example-VerifierError-RetrieveFullLog
	var clientset = InitializeK8sClient()
	var ebpfMapSpecs = LoadMapSpecs()
	var ebpfObjects = LoadObjects(&ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  math.MaxUint32 >> 2,
		},
	})

	var networkPolicyMap = NetworkPolicyMap{m: make(map[string]NetworkPolicy)}
	var podMap = PodMap{m: make(map[string][]Pod)}
	var namespaceMap = NamespaceMap{m: make(map[string][]string)}

	var services = ServiceMap{m: make(map[string]Service)}
	var maps = EBPFMapOfMaps{m: make(map[programKey]*ebpf.Map)}

	serviceEventHandlerLb := ServiceEventHandlerFuncs{
		AddHandler:    handleAddService(ebpfMapSpecs.Endpoints, ebpfObjects, &maps),
		DeleteHandler: handleDeleteService(ebpfObjects, &maps),
		UpdateHandler: handleUpdateService(ebpfMapSpecs.Endpoints, ebpfObjects, &maps),
	}

	serviceEventHandlerNp := NetworkPolicyEventHandlerFuncs{
		AddHandler:       handleAddNetworkPolicy(ebpfObjects, &podMap, &namespaceMap),
		DeleteHandler:    handleDeleteNetworkPolicy(ebpfObjects, &podMap, &namespaceMap),
		UpdateHandler:    handleUpdateNetworkPolicy(ebpfObjects, &podMap, &namespaceMap),
		AddPodHandler:    handleAddPod(ebpfObjects, &podMap, &namespaceMap, &networkPolicyMap),
		DeletePodHandler: handleDeletePod(ebpfObjects, &podMap, &namespaceMap, &networkPolicyMap),
	}

	var namespace = "default"
	if envNamespace := os.Getenv("WATCH_NAMESPACE"); envNamespace != "" {
		namespace = envNamespace
	}

	var networkPolicyController, podController, serviceControllerNp, namespaceController = WatchNetworkPolicy(clientset, "default", &networkPolicyMap, &podMap, &namespaceMap, serviceEventHandlerNp)
	var serviceController, endpointsController = WatchService(clientset, namespace, &services, serviceEventHandlerLb)

	stop := make(chan struct{})

	go serviceController.Run(stop)
	go endpointsController.Run(stop)
	go namespaceController.Run(stop)
	go podController.Run(stop)
	go serviceControllerNp.Run(stop)
	go networkPolicyController.Run(stop)
	go asyncResetCounter[programIpv4Key](*ebpfObjects.PktCount)

	attachEbpf(ebpfObjects)
}

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
