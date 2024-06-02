package main

import (
	"log"

	"github.com/cilium/ebpf"
	v1 "k8s.io/api/networking/v1"
)

func handleAddNetworkPolicy(objs *programObjects, podMap *PodMap, namespaceMap *NamespaceMap) func(networkpolicy NetworkPolicy) {
	return func(networkPolicy NetworkPolicy) {
		applicablePods := getPodIpsFromMatchLabel(podMap, networkPolicy.MatchLabel)

		addEbpfPolicies(objs.NetworkPolicyMap, podMap, namespaceMap, networkPolicy, applicablePods)
	}
}

func handleDeleteNetworkPolicy(objs *programObjects, podMap *PodMap, namespaceMap *NamespaceMap) func(networkPolicy NetworkPolicy) {
	return func(networkPolicy NetworkPolicy) {
		applicablePods := getPodIpsFromMatchLabel(podMap, networkPolicy.MatchLabel)

		deleteEbpfPolicies(objs.NetworkPolicyMap, podMap, namespaceMap, networkPolicy, applicablePods)
	}
}

func handleUpdateNetworkPolicy(objs *programObjects, podMap *PodMap, namespaceMap *NamespaceMap) func(oldNetworkPolicy NetworkPolicy, newNetworkPolicy NetworkPolicy) {
	return func(oldNetworkPolicy NetworkPolicy, newNetworkPolicy NetworkPolicy) {
		handleDeleteNetworkPolicy(objs, podMap, namespaceMap)(oldNetworkPolicy)
		handleAddNetworkPolicy(objs, podMap, namespaceMap)(newNetworkPolicy)
	}
}

func handleAddPod(objs *programObjects, podMap *PodMap, namespaceMap *NamespaceMap, networkPolicyMap *NetworkPolicyMap) func(podIp uint32, matchLabels map[string]string) {
	return func(podIp uint32, matchLabels map[string]string) {
		networkPolicyMap.RLock()

		for _, affectedNetworkPolicy := range networkPolicyMap.m {
			applicablePods := getPodIpsFromMatchLabel(podMap, affectedNetworkPolicy.MatchLabel)
			addEbpfPolicies(objs.NetworkPolicyMap, podMap, namespaceMap, affectedNetworkPolicy, applicablePods)
		}
		networkPolicyMap.RUnlock()
	}
}

func handleDeletePod(objs *programObjects, podMap *PodMap, namespaceMap *NamespaceMap, networkPolicyMap *NetworkPolicyMap) func(podIp uint32, matchLabels map[string]string) {
	return func(podIp uint32, matchLabels map[string]string) {

		networkPolicyMap.RLock()

		for _, affectedNetworkPolicy := range networkPolicyMap.m {
			applicablePods := getPodIpsFromMatchLabel(podMap, affectedNetworkPolicy.MatchLabel)
			deleteEbpfPolicies(objs.NetworkPolicyMap, podMap, namespaceMap, affectedNetworkPolicy, applicablePods)
		}

		networkPolicyMap.RUnlock()
	}
}

func addEbpfPolicies(ebpfMap *ebpf.Map, podMap *PodMap, namespaceMap *NamespaceMap, networkPolicy NetworkPolicy, applicablePods []uint32) {
	constructedKeys, constructedValues := constructEbpfNetworkPolicies(podMap, namespaceMap, networkPolicy, applicablePods)
	// printNetworkPolicyParis(constructedKeys, constructedValues)
	ebpfMap.BatchUpdate(constructedKeys, constructedValues, &ebpf.BatchOptions{})
}

func deleteEbpfPolicies(ebpfMap *ebpf.Map, podMap *PodMap, namespaceMap *NamespaceMap, networkPolicy NetworkPolicy, applicablePods []uint32) {
	constructedKeys, _ := constructEbpfNetworkPolicies(podMap, namespaceMap, networkPolicy, applicablePods)
	ebpfMap.BatchDelete(constructedKeys, &ebpf.BatchOptions{})
}

func constructEbpfNetworkPolicies(podMap *PodMap, namespaceMap *NamespaceMap, networkPolicy NetworkPolicy, applicablePods []uint32) ([]programKey, []uint32) {
	containsEgress := false
	containsIngress := false

	for _, pType := range networkPolicy.PolicyTypes {
		if pType == "Egress" {
			containsEgress = true
		}
		if pType == "Ingress" {
			containsIngress = true
		}
	}

	constructedPoliciyKeys := make([]programKey, 0)
	constructedPoliciyValues := make([]uint32, 0)

	if containsEgress {
		if len(networkPolicy.Egress) == 0 {
			// All Egress allowed
		} else {
			// By default deny all egress traffic
			denyKeys := make([]programKey, len(applicablePods))
			denyVals := make([]uint32, len(applicablePods))

			for index, podIp := range applicablePods {
				denyKeys[index] = ConstructKey(podIp, 0)
				denyVals[index] = 0
			}

			constructedPoliciyKeys = append(constructedPoliciyKeys, denyKeys...)
			constructedPoliciyValues = append(constructedPoliciyValues, denyVals...)

			// Allow only the specified egress rules
			allowedEgressPods := make([]uint32, 0)
			for _, ingressRule := range networkPolicy.Egress {
				if len(ingressRule.To) > 0 {
					allowedEgressPods = append(allowedEgressPods, getSelectedPodsFromPolicies(podMap, namespaceMap, ingressRule.To)...)
				}
			}

			acceptKeys := make([]programKey, len(applicablePods)*len(allowedEgressPods))
			acceptVals := make([]uint32, len(applicablePods)*len(allowedEgressPods))

			index := 0
			for _, applicablePod := range applicablePods {
				for _, allowedEgressPod := range allowedEgressPods {
					acceptKeys[index] = ConstructKey(applicablePod, allowedEgressPod)
					acceptVals[index] = 1

					index++
				}
			}

			constructedPoliciyKeys = append(constructedPoliciyKeys, acceptKeys...)
			constructedPoliciyValues = append(constructedPoliciyValues, acceptVals...)
		}
	}

	if containsIngress {
		if len(networkPolicy.Ingress) == 0 {
			// All Ingress allowed
		} else {
			// By default deny all ingress traffic
			denyKeys := make([]programKey, len(applicablePods))
			denyVals := make([]uint32, len(applicablePods))

			for index, podIp := range applicablePods {
				denyKeys[index] = ConstructKey(0, podIp)
				denyVals[index] = 0
			}

			constructedPoliciyKeys = append(constructedPoliciyKeys, denyKeys...)
			constructedPoliciyValues = append(constructedPoliciyValues, denyVals...)

			// Allow only the specified ingress rules
			allowedIngressPods := make([]uint32, 0)
			for _, ingressRule := range networkPolicy.Ingress {
				if len(ingressRule.From) > 0 {
					allowedIngressPods = append(allowedIngressPods, getSelectedPodsFromPolicies(podMap, namespaceMap, ingressRule.From)...)
				}
			}

			acceptKeys := make([]programKey, len(applicablePods)*len(allowedIngressPods))
			acceptVals := make([]uint32, len(applicablePods)*len(allowedIngressPods))

			index := 0
			for _, applicablePod := range applicablePods {
				for _, allowedallowedIngressPod := range allowedIngressPods {
					acceptKeys[index] = ConstructKey(allowedallowedIngressPod, applicablePod)
					acceptVals[index] = 1

					index++
				}
			}
			constructedPoliciyKeys = append(constructedPoliciyKeys, acceptKeys...)
			constructedPoliciyValues = append(constructedPoliciyValues, acceptVals...)
		}
	}

	if len(constructedPoliciyKeys) != len(constructedPoliciyValues) {
		log.Fatalf("keys %d and values %d are not of equal length", len(constructedPoliciyKeys), len(constructedPoliciyValues))
	}
	return constructedPoliciyKeys, constructedPoliciyValues
}

func getSelectedPodsFromPolicies(podMap *PodMap, namespaceMap *NamespaceMap, policies []v1.NetworkPolicyPeer) []uint32 {
	pods := make([]uint32, 0)
	podMap.RLock()
	namespaceMap.RLock()

	for _, policy := range policies {
		if policy.PodSelector != nil && policy.NamespaceSelector != nil {
			intersectMap := make(map[uint32]bool)

			// Find all IPs that match the PodSelector labels
			for label, val := range policy.PodSelector.MatchLabels {
				combined := combineMatchLabel(label, val)
				if val, exists := podMap.m[combined]; exists {
					for _, pod := range val {
						intersectMap[pod.IP] = true
					}
				}
			}

			// Append all pods that intersect PodSelector labels and NamespaceSelector labels if both PodSelector and Namespace selector is set
			for label, val := range policy.NamespaceSelector.MatchLabels {
				combined := combineMatchLabel(label, val)
				if namespaceNames, exists := namespaceMap.m[combined]; exists {
					for _, name := range namespaceNames {
						for _, pod := range podMap.m[name] {
							if _, exists := intersectMap[pod.IP]; exists {
								pods = append(pods, pod.IP)
							}
						}
					}
				}
			}

			// Append all pods that match PodSelector if only PodSelector is set
		} else if policy.PodSelector != nil {
			for label, val := range policy.PodSelector.MatchLabels {
				combined := combineMatchLabel(label, val)
				if val, exists := podMap.m[combined]; exists {
					pods = append(pods, convertPodStructsToUInt32Array(val)...)
				}
			}
			// Append all pods that match NamespaceSelector if only Namespace selector is set
		} else if policy.NamespaceSelector != nil {
			for label, val := range policy.NamespaceSelector.MatchLabels {
				combined := combineMatchLabel(label, val)
				if namespaceNames, exists := namespaceMap.m[combined]; exists {
					for _, name := range namespaceNames {
						pods = append(pods, convertPodStructsToUInt32Array(podMap.m[name])...)

					}
				}
			}
		}
	}
	namespaceMap.RUnlock()
	podMap.RUnlock()

	return pods
}

func getPodIpsFromMatchLabel(podMap *PodMap, matchLabel map[string]string) []uint32 {
	podIps := make([]uint32, 0)

	for label, val := range matchLabel {
		combined := combineMatchLabel(label, val)
		if ipList, exists := podMap.m[combined]; exists {
			podIps = append(podIps, convertPodStructsToUInt32Array(ipList)...)
		}
	}

	return podIps
}

func convertPodStructsToUInt32Array(pods []Pod) []uint32 {
	ips := make([]uint32, len(pods))
	for index, pod := range pods {
		ips[index] = pod.IP
	}
	return ips
}

func combineMatchLabel(label string, value string) string {
	return label + "=" + value
}
