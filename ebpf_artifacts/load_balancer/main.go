package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event program  program.bpf.c

import (
	"math"
	"os"
	"sync"

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

	var services = ServiceMap{m: make(map[string]Service)}
	var maps = EBPFMapOfMaps{m: make(map[programKey]*ebpf.Map)}

	serviceEventHandler := ServiceEventHandlerFuncs{
		AddHandler:    handleAddService(ebpfMapSpecs.Endpoints, ebpfObjects, &maps),
		DeleteHandler: handleDeleteService(ebpfObjects, &maps),
		UpdateHandler: handleUpdateService(ebpfMapSpecs.Endpoints, ebpfObjects, &maps),
	}

	var namespace = "default"
	if envNamespace := os.Getenv("WATCH_NAMESPACE"); envNamespace != "" {
		namespace = envNamespace
	}

	var serviceController, endpointsController = WatchService(clientset, namespace, &services, serviceEventHandler)
	stop := make(chan struct{})

	go serviceController.Run(stop)
	go endpointsController.Run(stop)

	attachEbpf(ebpfObjects)
}
