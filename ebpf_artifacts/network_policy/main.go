package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event program program.bpf.c

import (
	"math"
	"sync"

	"github.com/cilium/ebpf"
)

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
	// var ebpfMapSpecs = LoadMapSpecs()
	var ebpfObjects = LoadObjects(&ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  math.MaxUint32 >> 2,
		},
	})

	var networkPolicyMap = NetworkPolicyMap{m: make(map[string]NetworkPolicy)}
	var podMap = PodMap{m: make(map[string][]Pod)}
	var namespaceMap = NamespaceMap{m: make(map[string][]string)}

	serviceEventHandler := NetworkPolicyEventHandlerFuncs{
		AddHandler:       handleAddNetworkPolicy(ebpfObjects, &podMap, &namespaceMap),
		DeleteHandler:    handleDeleteNetworkPolicy(ebpfObjects, &podMap, &namespaceMap),
		UpdateHandler:    handleUpdateNetworkPolicy(ebpfObjects, &podMap, &namespaceMap),
		AddPodHandler:    handleAddPod(ebpfObjects, &podMap, &namespaceMap, &networkPolicyMap),
		DeletePodHandler: handleDeletePod(ebpfObjects, &podMap, &namespaceMap, &networkPolicyMap),
	}

	var networkPolicyController, podController, serviceController, namespaceController = WatchNetworkPolicy(clientset, "default", &networkPolicyMap, &podMap, &namespaceMap, serviceEventHandler)
	stop := make(chan struct{})

	go namespaceController.Run(stop)
	go podController.Run(stop)
	go serviceController.Run(stop)
	go networkPolicyController.Run(stop)

	attachEbpf(ebpfObjects)
}
