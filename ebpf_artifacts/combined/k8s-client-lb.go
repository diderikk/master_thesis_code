package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const IP_SIZE = 4

type IP uint32

type Endpoint struct {
	IP          IP
	Port        uint16
	ServicePort uint16
}

type Service struct {
	ClusterIP                  IP
	TargetPortToServicePortMap map[uint16]uint16
	Endpoints                  []Endpoint
}

type ServiceEventHandlerFuncs struct {
	AddHandler    func(Service)
	UpdateHandler func(uint32, []uint16, Service)
	DeleteHandler func(uint32, []uint16)
}

func InitializeK8sClient() *kubernetes.Clientset {
	config, err := rest.InClusterConfig()
	if err != nil {
		var kubeconfig *string
		home := "/home/diderikk"
		if _, err := os.Stat(filepath.Join(home, ".kube", "config")); home != "" && err == nil {
			kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		}
		flag.Parse()

		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			panic(err.Error())
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	return clientset
}

func WatchService(clientset *kubernetes.Clientset, namespace string, serviceMap *ServiceMap, handlers ServiceEventHandlerFuncs) (cache.Controller, cache.Controller) {
	serviceWatchlist := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "services", namespace, fields.Everything())
	endpointWatchlist := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "endpoints", namespace, fields.Everything())

	_, serviceController := cache.NewInformer(serviceWatchlist, &v1.Service{}, 0*time.Second, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			service := obj.(*v1.Service)
			s := updateServiceMap(serviceMap, service)

			handlers.AddHandler(s)
		},

		DeleteFunc: func(obj interface{}) {
			service := obj.(*v1.Service)
			deleteServiceMapEntry(serviceMap, service.Name)

			servicePorts := make([]uint16, len(service.Spec.Ports))

			for index, port := range service.Spec.Ports {
				servicePorts[index] = uint16(port.Port)
			}

			handlers.DeleteHandler(uint32(IPStringToInt(service.Spec.ClusterIP)), servicePorts)
		},

		UpdateFunc: func(oldObj, newObj interface{}) {
			service := newObj.(*v1.Service)
			oldService := oldObj.(*v1.Service)

			if oldService.Name != service.Name {
				deleteServiceMapEntry(serviceMap, oldService.Name)
			}
			s := updateServiceMap(serviceMap, service)

			servicePorts := make([]uint16, len(service.Spec.Ports))

			for index, port := range service.Spec.Ports {
				servicePorts[index] = uint16(port.Port)
			}

			handlers.UpdateHandler(uint32(IPStringToInt(oldService.Name)), servicePorts, s)
		},
	})

	_, endpointsController := cache.NewInformer(endpointWatchlist, &v1.Endpoints{}, 0*time.Second, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			endpoints := obj.(*v1.Endpoints)
			s := updateServiceMapEnpoints(serviceMap, *endpoints)

			handlers.AddHandler(s)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			endpoints := newObj.(*v1.Endpoints)
			oldEndpoints := oldObj.(*v1.Endpoints)
			s := updateServiceMapEnpoints(serviceMap, *endpoints)

			servicePorts := make([]uint16, len(s.TargetPortToServicePortMap))

			i := 0
			for _, servicePort := range s.TargetPortToServicePortMap {
				servicePorts[i] = servicePort
				i++
			}

			handlers.UpdateHandler(uint32(IPStringToInt(oldEndpoints.Name)), servicePorts, s)
		},
	})
	return serviceController, endpointsController
}

func updateServiceMap(serviceMap *ServiceMap, service *v1.Service) Service {
	portsMap := make(map[uint16]uint16, len(service.Spec.Ports))

	for _, servicePort := range service.Spec.Ports {
		portsMap[uint16(servicePort.TargetPort.IntVal)] = uint16(servicePort.Port)
	}

	serviceMap.RWMutex.Lock()

	endpoints := serviceMap.m[service.Name].Endpoints

	for index, endpoint := range endpoints {
		endpoints[index].ServicePort = portsMap[endpoint.Port]
	}

	s := Service{
		TargetPortToServicePortMap: portsMap,
		ClusterIP:                  IP(IPStringToInt(service.Spec.ClusterIP)),
		Endpoints:                  endpoints,
	}

	serviceMap.m[service.Name] = s

	serviceMap.RWMutex.Unlock()

	return s
}

func updateServiceMapEnpoints(serviceMap *ServiceMap, endpoints v1.Endpoints) Service {
	generatedEndpointSubsets := make([][]Endpoint, len(endpoints.Subsets))
	totalSize := 0
	for index, endpointSubset := range endpoints.Subsets {
		endpointSubsets := endpointSubsetToStruct(endpointSubset)
		generatedEndpointSubsets[index] = endpointSubsets
		totalSize += len(endpointSubsets)
	}

	serviceMap.RWMutex.Lock()

	index := 0
	flattenedGeneratedEndpoints := make([]Endpoint, totalSize)
	for _, subset := range generatedEndpointSubsets {
		for _, endpoint := range subset {
			flattenedGeneratedEndpoints[index] = endpoint
			flattenedGeneratedEndpoints[index].ServicePort = serviceMap.m[endpoints.Name].TargetPortToServicePortMap[endpoint.Port]
			index++
		}
	}

	s := Service{
		TargetPortToServicePortMap: serviceMap.m[endpoints.Name].TargetPortToServicePortMap,
		ClusterIP:                  serviceMap.m[endpoints.Name].ClusterIP,
		Endpoints:                  flattenedGeneratedEndpoints,
	}

	serviceMap.m[endpoints.Name] = s

	serviceMap.RWMutex.Unlock()

	return s
}

func deleteServiceMapEntry(serviceMap *ServiceMap, entryKey string) {
	serviceMap.Lock()
	delete(serviceMap.m, entryKey)
	serviceMap.Unlock()
}

func FormatPorts(ports map[uint32]uint32) string {
	formatString := ""
	for port, targetPort := range ports {
		formatString += fmt.Sprintf("(Port: %d, TargetPort: %d)", port, targetPort)
	}
	return formatString
}

func FormatEndpoints(endpoints []Endpoint) string {
	endpointsStringified := make([]string, len(endpoints))

	for i, endpoint := range endpoints {
		endpointsStringified[i] = fmt.Sprintf("(Address: %s, Port: %d, SourcePort: %d)", IPIntToString(endpoint.IP), endpoint.Port, endpoint.ServicePort)
	}

	return strings.Join(endpointsStringified, ",")
}

func IPStringToIntArray(ip string) [4]uint8 {
	var array [4]uint8
	bytes := strings.Split(ip, ".")

	for i, byte_ := range bytes {
		integerValue, err := strconv.Atoi(byte_)
		if err != nil {
			log.Printf("Failed to list filters: %v", err)
		}
		array[i] = uint8(integerValue)
	}

	return array
}

func IPIntToString(sourceAddress IP) string {
	var bytes = make([]uint8, 4)
	bytes[0] = uint8(sourceAddress & 0xFF)
	bytes[1] = uint8(sourceAddress>>8) & 0xFF
	bytes[2] = uint8(sourceAddress>>16) & 0xFF
	bytes[3] = uint8(sourceAddress>>24) & 0xFF

	return fmt.Sprintf("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0])
}

func endpointSubsetToStruct(subset v1.EndpointSubset) []Endpoint {
	var size = len(subset.Addresses) * len(subset.Ports)
	endpoints := make([]Endpoint, size)

	var index = 0

	for _, address := range subset.Addresses {
		for _, port := range subset.Ports {
			endpoints[index] = Endpoint{IP: IP(IPStringToInt(address.IP)), Port: uint16(port.Port)}

			index += 1
		}
	}

	return endpoints
}
