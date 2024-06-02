package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event program program.bpf.c

import (
	"math"
	"sync"

	"github.com/cilium/ebpf"
)

type IPMap struct {
	sync.RWMutex
	m map[uint32]string
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

	var podMap = IPMap{m: make(map[uint32]string)}
	// var interfaceList = IfList{list: []string{}}

	var podController, serviceController = WatchPodAndService(clientset, &podMap)
	stop := make(chan struct{})

	go podController.Run(stop)
	go serviceController.Run(stop)

	attachEbpf(ebpfObjects)
}
