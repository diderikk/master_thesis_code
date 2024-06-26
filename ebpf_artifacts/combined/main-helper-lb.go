package main

import (
	"log"

	"github.com/cilium/ebpf"
)

func handleAddService(spec *ebpf.MapSpec, objs *programObjects, ebpfMapofMap *EBPFMapOfMaps) func(service Service) {
	return func(service Service) {
		// Checks if all values has been set (uint32 default value is 0)
		if service.ClusterIP > 0 &&
			len(service.TargetPortToServicePortMap) > 0 &&
			len(service.Endpoints) > 0 {
			// Generates a new service map. Key: Service Port
			servicePortToNewEbpfMaps := make(map[uint16]*ebpf.Map, len(service.TargetPortToServicePortMap))

			for _, servicePort := range service.TargetPortToServicePortMap {
				servicePortToNewEbpfMaps[servicePort] = GenerateMap(spec)
			}

			// Adds all endpoints to the eBPF service map
			servicePortToEndpointAmounts := addAllEndpointsToEbpfServiceMaps(service, servicePortToNewEbpfMaps)

			addEbpfServiceMapsToEbpfMapOfMapsAndMemory(uint32(service.ClusterIP), servicePortToNewEbpfMaps, servicePortToEndpointAmounts, objs, ebpfMapofMap)
		}
	}
}

func handleDeleteService(objs *programObjects, ebpfMapofMap *EBPFMapOfMaps) func(ip uint32, servicePorts []uint16) {
	return func(ip uint32, servicePorts []uint16) {
		ebpfMapofMap.RLock()

		for _, servicePort := range servicePorts {
			key := ConstructKey(ip, uint32(servicePort))

			mapEntry := ebpfMapofMap.m[key]
			if mapEntry != nil {
				// Closes the eBPF map, could be that this also removes it from the eBPF map of maps aswell
				// Since the map should have lost all pins, the eBPF map will be removed by the kernel
				err := mapEntry.Close()

				if err != nil {
					log.Printf("Failed to list filters: %v", err)
				}
			}
		}

		ebpfMapofMap.RUnlock()

		// Deletes the service endpoints map from the eBPF map of maps and memory
		deleteEbpfServiceMapsFromEbpfMapOfMapsAndMemory(ip, servicePorts, objs, ebpfMapofMap)
	}
}

func handleUpdateService(spec *ebpf.MapSpec, objs *programObjects, ebpfMapofMap *EBPFMapOfMaps) func(oldIp uint32, oldServicePorts []uint16, service Service) {
	return func(oldIp uint32, oldServicePorts []uint16, newService Service) {
		handleDeleteService(objs, ebpfMapofMap)(oldIp, oldServicePorts)
		handleAddService(spec, objs, ebpfMapofMap)(newService)
	}
}

func addAllEndpointsToEbpfServiceMaps(service Service, ebpfMaps map[uint16]*ebpf.Map) map[uint16]uint16 {
	keysMap, valuesMap := convertServiceEndpointsToEbpfEndpoints(uint32(service.ClusterIP), service.Endpoints)
	servicePortToEndpointAmounts := make(map[uint16]uint16, len(keysMap))

	totalInserted := 0

	for servicePort, keys := range keysMap {
		inserted, err := ebpfMaps[servicePort].BatchUpdate(keys, valuesMap[servicePort], &ebpf.BatchOptions{})
		if err != nil {
			log.Printf("Failed to list filters: %v", err)
		}
		servicePortToEndpointAmounts[servicePort] = uint16(inserted)

		totalInserted += inserted
	}

	if totalInserted < len(service.Endpoints) {
		log.Fatalf("Number of inserted endpoints %d does not match amount of endpoints %d", totalInserted, len(service.Endpoints))
		for _, ebpfMap := range ebpfMaps {
			ebpfMap.Close()
		}
	}

	return servicePortToEndpointAmounts
}

func convertServiceEndpointsToEbpfEndpoints(serviceClusterIP uint32, serivceEndpoints []Endpoint) (map[uint16][]uint32, map[uint16][]programEndpoint) {
	keys := make(map[uint16][]uint32, len(serivceEndpoints))
	values := make(map[uint16][]programEndpoint, len(serivceEndpoints))

	for _, endpoint := range serivceEndpoints {
		epStruct := programEndpoint{
			Ip:   uint32(endpoint.IP),
			Port: endpoint.Port,
		}
		values[endpoint.ServicePort] = append(values[endpoint.ServicePort], epStruct)
		keys[endpoint.ServicePort] = append(keys[endpoint.ServicePort], uint32(len(keys[endpoint.ServicePort])))
	}

	return keys, values
}

func addEbpfServiceMapsToEbpfMapOfMapsAndMemory(ip uint32, servicePortToEbpfMaps map[uint16]*ebpf.Map, servicePortToEndpointAmounts map[uint16]uint16, objs *programObjects, ebpfMapofMap *EBPFMapOfMaps) {
	ebpfMapofMap.Lock()

	// Adds the new map to the eBPF map of maps (map that contains all eBPF service maps)
	for servicePort, ebpfMap := range servicePortToEbpfMaps {
		key := ConstructKey(ip, uint32(servicePort))
		meta := ConstructMeta(servicePortToEndpointAmounts[servicePort], int32(ebpfMap.FD()))
		err := objs.programMaps.ServiceRefMetaMap.Update(key, meta, ebpf.UpdateNoExist)
		if err != nil {
			log.Printf("Failed to list filters: %v", err)
		}

		err = objs.programMaps.ServiceRefsMap.Update(key, int32(ebpfMap.FD()), ebpf.UpdateNoExist)
		if err != nil {
			log.Printf("Failed to list filters: %v", err)
		}

		ebpfMapofMap.m[key] = ebpfMap
	}

	ebpfMapofMap.Unlock()
}

func deleteEbpfServiceMapsFromEbpfMapOfMapsAndMemory(ip uint32, servicePorts []uint16, objs *programObjects, ebpfMapofMap *EBPFMapOfMaps) {
	ebpfMapofMap.Lock()
	// Deletes the new map to the eBPF map of maps (map that contains all eBPF service maps)
	for _, servicePort := range servicePorts {
		key := ConstructKey(ip, uint32(servicePort))
		err := objs.programMaps.ServiceRefsMap.Delete(key)
		if err != nil {
			log.Printf("Failed to list filters: %v", err)
		}

		err = objs.programMaps.ServiceRefMetaMap.Delete(key)

		if err != nil {
			log.Printf("Failed to list filters: %v", err)
		}

		delete(ebpfMapofMap.m, key)
	}

	ebpfMapofMap.Unlock()
}
