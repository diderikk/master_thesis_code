package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type NetworkPolicy struct {
	MatchLabel  map[string]string
	PolicyTypes []string
	Egress      []netv1.NetworkPolicyEgressRule
	Ingress     []netv1.NetworkPolicyIngressRule
}

type Pod struct {
	IP        uint32
	Namespace string
}

type NetworkPolicyEventHandlerFuncs struct {
	AddHandler       func(NetworkPolicy)
	UpdateHandler    func(NetworkPolicy, NetworkPolicy)
	DeleteHandler    func(NetworkPolicy)
	AddPodHandler    func(uint32, map[string]string)
	DeletePodHandler func(uint32, map[string]string)
}

// Initializes a golang Kubernetes client, similar to kubectl
// When deployed inside a cluster, this configuration automatically initializes
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

// Continously watches for changes in the Kubernetes cluster related to services and pod resources
func WatchPodAndService(clientset *kubernetes.Clientset, ipMap *IPMap) (cache.Controller, cache.Controller) {
	podWatchList := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "pods", v1.NamespaceAll, fields.Everything())
	serviceWatchList := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "services", v1.NamespaceAll, fields.Everything())

	_, podController := cache.NewInformer(podWatchList, &v1.Pod{}, 0*time.Second, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)

			// Some pods are in a COMPLETED Status, and therefore does not have an IP
			podIp := IPStringToInt(pod.Status.PodIP)
			if pod.Status.Phase == "Failed" || pod.Status.Phase == "Success" || podIp == 0 {
				return
			}

			updateIpMap(ipMap, podIp, pod.Name)
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)

			// Some pods are in a COMPLETED Status, and therefore does not have an IP
			podIp := IPStringToInt(pod.Status.PodIP)
			if pod.Status.Phase == "Failed" || pod.Status.Phase == "Success" || podIp == 0 {
				return
			}

			deleteIpMapEntry(ipMap, podIp)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newPod := newObj.(*v1.Pod)
			oldPod := oldObj.(*v1.Pod)

			// Some pods are in a COMPLETED Status, and therefore does not have an IP
			podIp := IPStringToInt(newPod.Status.PodIP)
			if newPod.Status.Phase == "Failed" || newPod.Status.Phase == "Success" || podIp == 0 {
				return
			}
			deleteIpMapEntry(ipMap, IPStringToInt(oldPod.Status.PodIP))
			updateIpMap(ipMap, podIp, newPod.Name)
		},
	})

	_, serviceController := cache.NewInformer(serviceWatchList, &v1.Service{}, 0*time.Second, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			service := obj.(*v1.Service)

			serviceIp := IPStringToInt(service.Spec.ClusterIP)
			if serviceIp == 0 {
				return
			}

			updateIpMap(ipMap, serviceIp, service.Name)
		},
		DeleteFunc: func(obj interface{}) {
			service := obj.(*v1.Service)

			serviceIp := IPStringToInt(service.Spec.ClusterIP)
			if serviceIp == 0 {
				return
			}

			deleteIpMapEntry(ipMap, serviceIp)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newService := newObj.(*v1.Service)
			oldService := oldObj.(*v1.Service)

			oldServiceIp := IPStringToInt(oldService.Spec.ClusterIP)
			deleteIpMapEntry(ipMap, oldServiceIp)

			newServiceIp := IPStringToInt(newService.Spec.ClusterIP)
			if newServiceIp == 0 {
				return
			}

			updateIpMap(ipMap, newServiceIp, newService.Name)
		},
	})
	return podController, serviceController
}

func updateIpMap(podMap *IPMap, ip uint32, name string) {
	podMap.Lock()
	// fmt.Printf("Pod map updated %s\n", pod.Name)

	podMap.m[ip] = name

	podMap.Unlock()
}

func deleteIpMapEntry(podMap *IPMap, ip uint32) {
	podMap.Lock()

	delete(podMap.m, ip)

	podMap.Unlock()
}

func FormatPorts(ports map[uint32]uint32) string {
	formatString := ""
	for port, targetPort := range ports {
		formatString += fmt.Sprintf("(Port: %d, TargetPort: %d)", port, targetPort)
	}
	return formatString
}

func IPStringToInt(ip string) uint32 {
	net := net.ParseIP(ip)
	if net == nil {
		return 0
	}
	net = net.To4()
	return uint32(binary.BigEndian.Uint32(net))
}
