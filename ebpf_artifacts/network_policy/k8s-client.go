package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"time"

	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// Continously watches for changes in the Kubernetes cluster related to pods, services, namespaces or network policies
func WatchNetworkPolicy(clientset *kubernetes.Clientset, namespace string, networkPolicyMap *NetworkPolicyMap, podMap *PodMap, namespaceMap *NamespaceMap,
	handlers NetworkPolicyEventHandlerFuncs) (cache.Controller, cache.Controller, cache.Controller, cache.Controller) {
	// First fetches all namespaces inside the cluster
	namespaces, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err)
	} else {
		for _, namespace := range namespaces.Items {
			updateNamespaceMap(namespaceMap, &namespace)
		}
	}

	// All pods, services and namespaces are fetched, but only the network policies from a single namespace is fetched.
	podWatchList := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "pods", v1.NamespaceAll, fields.Everything())
	serviceWatchList := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "services", v1.NamespaceAll, fields.Everything())
	networkPolicyList := cache.NewListWatchFromClient(clientset.NetworkingV1().RESTClient(), "networkpolicies", namespace, fields.Everything())
	namespaceWatchList := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "namespaces", v1.NamespaceAll, fields.Everything())

	// Connects handler functions to the different events that occur related to the resources.
	_, networkPolicyController := cache.NewInformer(networkPolicyList, &netv1.NetworkPolicy{}, 0*time.Second, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			networkPolicy := obj.(*netv1.NetworkPolicy)
			s := updateNetworkPolicyMap(networkPolicyMap, networkPolicy)

			handlers.AddHandler(s)
		},

		DeleteFunc: func(obj interface{}) {
			networkPolicy := obj.(*netv1.NetworkPolicy)

			deleteNetworkPolicyMapEntry(networkPolicyMap, networkPolicy.Name)

			handlers.DeleteHandler(convertV1NetworkPolicyToLocalNetworkPolicyStruct(*networkPolicy))
		},

		UpdateFunc: func(oldObj, newObj interface{}) {
			newNetworkPolicy := newObj.(*netv1.NetworkPolicy)
			oldNetworkPolicy := oldObj.(*netv1.NetworkPolicy)

			if oldNetworkPolicy.Name != newNetworkPolicy.Name {
				deleteNetworkPolicyMapEntry(networkPolicyMap, oldNetworkPolicy.Name)
			}
			s := updateNetworkPolicyMap(networkPolicyMap, newNetworkPolicy)

			convertedOldNetworkPolicy := convertV1NetworkPolicyToLocalNetworkPolicyStruct(*oldNetworkPolicy)
			handlers.UpdateHandler(convertedOldNetworkPolicy, s)
		},
	})

	_, podController := cache.NewInformer(podWatchList, &v1.Pod{}, 0*time.Second, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)

			// Some pods are in a COMPLETED Status, and therefore does not have an IP
			podIp := IPStringToInt(pod.Status.PodIP)
			if pod.Status.Phase == "Failed" || pod.Status.Phase == "Success" || podIp == 0 {
				return
			}

			handlers.DeletePodHandler(podIp, pod.Labels)
			updatePodMap(podMap, podIp, pod.Namespace, pod.Labels)
			handlers.AddPodHandler(podIp, pod.Labels)
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)

			// Some pods are in a COMPLETED Status, and therefore does not have an IP
			podIp := IPStringToInt(pod.Status.PodIP)
			if pod.Status.Phase == "Failed" || pod.Status.Phase == "Success" || podIp == 0 {
				return
			}

			handlers.DeletePodHandler(podIp, pod.Labels)
			deletePodMapEntry(podMap, podIp, pod.Namespace, pod.Labels)
			handlers.AddPodHandler(podIp, pod.Labels)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newPod := newObj.(*v1.Pod)
			oldPod := oldObj.(*v1.Pod)

			// Some pods are in a COMPLETED Status, and therefore does not have an IP
			podIp := IPStringToInt(newPod.Status.PodIP)
			if newPod.Status.Phase == "Failed" || newPod.Status.Phase == "Success" || podIp == 0 {
				return
			}

			handlers.DeletePodHandler(IPStringToInt(oldPod.Status.PodIP), oldPod.Labels)

			deletePodMapEntry(podMap, IPStringToInt(oldPod.Status.PodIP), oldPod.Namespace, oldPod.Labels)
			updatePodMap(podMap, podIp, newPod.Namespace, newPod.Labels)

			handlers.AddPodHandler(podIp, newPod.Labels)
		},
	})

	_, serviceController := cache.NewInformer(serviceWatchList, &v1.Service{}, 0*time.Second, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			service := obj.(*v1.Service)

			handlers.DeletePodHandler(IPStringToInt(service.Spec.ClusterIP), service.Labels)
			updatePodMap(podMap, IPStringToInt(service.Spec.ClusterIP), service.Namespace, service.Labels)
			handlers.AddPodHandler(IPStringToInt(service.Spec.ClusterIP), service.Labels)
		},
		DeleteFunc: func(obj interface{}) {
			service := obj.(*v1.Service)

			handlers.DeletePodHandler(IPStringToInt(service.Spec.ClusterIP), service.Labels)
			deletePodMapEntry(podMap, IPStringToInt(service.Spec.ClusterIP), service.Namespace, service.Labels)
			handlers.AddPodHandler(IPStringToInt(service.Spec.ClusterIP), service.Labels)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newService := newObj.(*v1.Service)
			oldService := oldObj.(*v1.Service)

			handlers.DeletePodHandler(IPStringToInt(oldService.Spec.ClusterIP), oldService.Labels)

			deletePodMapEntry(podMap, IPStringToInt(oldService.Spec.ClusterIP), oldService.Namespace, oldService.Labels)
			updatePodMap(podMap, IPStringToInt(newService.Spec.ClusterIP), newService.Namespace, newService.Labels)

			handlers.AddPodHandler(IPStringToInt(newService.Spec.ClusterIP), newService.Labels)
		},
	})

	_, namespaceController := cache.NewInformer(namespaceWatchList, &v1.Namespace{}, 0*time.Second, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Namespace)
			updateNamespaceMap(namespaceMap, pod)
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*v1.Namespace)
			deleteNamespaceMapEntry(namespaceMap, pod)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newPod := newObj.(*v1.Namespace)
			oldPod := oldObj.(*v1.Namespace)
			deleteNamespaceMapEntry(namespaceMap, oldPod)
			updateNamespaceMap(namespaceMap, newPod)
		},
	})
	return networkPolicyController, podController, serviceController, namespaceController
}

// The following six functions are used to update maps that store the Kubernetes resources in memory
// Some also modify or extract data from the resource, in order to not use unecessary amount of memory.

func updateNetworkPolicyMap(networkPolicyMap *NetworkPolicyMap, networkPolicy *netv1.NetworkPolicy) NetworkPolicy {
	np := convertV1NetworkPolicyToLocalNetworkPolicyStruct(*networkPolicy)
	// fmt.Printf("Network Policy map updated %s\n", networkPolicy.Name)

	networkPolicyMap.RWMutex.Lock()

	networkPolicyMap.m[networkPolicy.Name] = np

	networkPolicyMap.RWMutex.Unlock()

	return np
}

func updatePodMap(podMap *PodMap, ip uint32, namespace string, labels map[string]string) uint32 {
	podMap.Lock()

	podStruct := Pod{IP: ip, Namespace: namespace}

	// Add all pod labels
	for label, value := range labels {
		combined := label + "=" + value
		if ipList, exists := podMap.m[combined]; exists && !isInSlice[Pod](ipList, podStruct) {
			podMap.m[combined] = append(ipList, podStruct)
		} else if !exists {
			podMap.m[combined] = []Pod{podStruct}
		}
	}

	if ipList, exists := podMap.m[namespace]; exists {
		podMap.m[namespace] = append(ipList, podStruct)
	} else {
		podMap.m[namespace] = []Pod{podStruct}
	}
	podMap.Unlock()

	return ip
}

func updateNamespaceMap(namespaceMap *NamespaceMap, namespace *v1.Namespace) {
	namespaceMap.Lock()
	// fmt.Printf("Namespace map updated %s\n", namespace.Name)
	for label, value := range namespace.Labels {
		combined := label + "=" + value
		if namespaceList, exists := namespaceMap.m[combined]; exists && !isInSlice[string](namespaceList, namespace.Name) {
			namespaceMap.m[combined] = append(namespaceList, namespace.Name)
		} else if !exists {
			namespaceMap.m[combined] = []string{namespace.Name}
		}
	}
	namespaceMap.Unlock()
}

func deleteNetworkPolicyMapEntry(networkPolicyMap *NetworkPolicyMap, entryKey string) {
	networkPolicyMap.Lock()
	delete(networkPolicyMap.m, entryKey)
	networkPolicyMap.Unlock()
}

func deletePodMapEntry(podMap *PodMap, ip uint32, namespace string, labels map[string]string) error {
	podMap.Lock()

	for label, value := range labels {
		combined := label + "=" + value
		if ipList, exists := podMap.m[combined]; exists {
			for index, _ip := range ipList {
				if _ip.IP == ip {
					ipList[index] = ipList[len(ipList)-1]
					podMap.m[combined] = ipList[:len(ipList)-1]
					break
				}
			}
		} else {
			return fmt.Errorf("missing label from podMap: %s", combined)
		}
	}

	podMap.Unlock()

	return nil
}

func deleteNamespaceMapEntry(namespaceMap *NamespaceMap, namespace *v1.Namespace) error {
	namespaceMap.Lock()

	for label, value := range namespace.Labels {
		combined := label + "=" + value
		if namespaceList, exists := namespaceMap.m[combined]; exists {
			for index, name := range namespaceList {
				if name == namespace.Name {
					namespaceList[index] = namespaceList[len(namespaceList)-1]
					namespaceMap.m[combined] = namespaceList[:len(namespaceList)-1]
					break
				}
			}
		} else {
			return fmt.Errorf("missing label from podMap: %s", combined)
		}
	}

	namespaceMap.Unlock()
	return nil
}

// Converts a Kubernetes Network Policy resource to a structure that is stored in memory
func convertV1NetworkPolicyToLocalNetworkPolicyStruct(networkPolicy netv1.NetworkPolicy) NetworkPolicy {
	policyTypes := make([]string, len(networkPolicy.Spec.PolicyTypes))
	for index, pt := range networkPolicy.Spec.PolicyTypes {
		policyTypes[index] = string(pt)
	}

	return NetworkPolicy{
		MatchLabel:  networkPolicy.Spec.PodSelector.MatchLabels,
		PolicyTypes: policyTypes,
		Egress:      networkPolicy.Spec.Egress,
		Ingress:     networkPolicy.Spec.Ingress,
	}
}

// Checks if item exists inside an array/list
func isInSlice[T any](slice []T, target T) bool {
	for _, item := range slice {
		if reflect.DeepEqual(item, target) {
			return true
		}
	}

	return false
}

func IPStringToInt(ip string) uint32 {
	net := net.ParseIP(ip)
	if net == nil {
		return 0
	}
	net = net.To4()
	return uint32(binary.BigEndian.Uint32(net))
}
