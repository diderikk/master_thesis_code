# eBPF artifact
This folder is a Golang project containing the developed eBPF artifacts. The artifacts are divided into four features, each mimicking a service mesh feature. The programs are compiled and typed using the [ebpf-go](https://ebpf-go.dev/) library. The eBPF program has only been compiled and deployed on Ubuntu 22.04 with kernel version `Linux 6.5.0-35-generic x86_64`.


## Modules
The 
* **bandwidth_management**: Implements packet-based rate limiting
* **load_balancer**: Implements packet-based load-balacing, replacing iptables. NB! Currently, it only works with pods communicating on the same node
* **network_policy**: Implements an eBPF-based network policy validator
* **observability**: Implmenents a simple flow packet counter

## Module structure
Each module is similar in structure:

* **Dockerfile**: The file used to define the container image.
* **packet.h**: Contains helper functions for handling network packets in C programming language. This file is highly based on: [Learning eBPF](https://github.com/lizrice/learning-ebpf/blob/main/chapter8/network.h) and [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial/blob/master/common/parsing_helpers.h)
* **program.bpf.c**: The eBPF program
* **eBPF.go**: Implements all the functionality related to eBPF, such as the functionality to deploy the eBPF program onto a network interface.
* **k8s-client.go**: Implements all the functionality related to communicating with the Kubernetes cluster.
* **main-helpers.go**: Helper functions that contain functionality to handle events occuring in the Kubernetes cluster. For example, they define how the program reacts when a new pod or network policy has been scheduled onto the cluster.
* **main.go**: Contains the main function that is called at program startup.

## Deployment

### Run locally
Either
```bash
go generate && go build && sudo ./<module_name>
```
or using GNU Make
```bash
cd <module_name> && make generate
```

### Docker (containerized)

```bash
cd <module_name> && docker build -t ebpf-go .

# Depending on if the program requires Kubernetes information, one need to provide the Kubernetes configs/token for the program to have access to Kubernetes resources.
# This might require an update in the InitializeK8sClient function in the corresponding k8s-client.go file.

docker run --rm --privileged --network host --mount type=bind,source=<KUBERNETES_CONFIG>,target=/root/.kube/config --name ebpf -e INTERFACE_SUBSTRING=<NETWORK_INTERFACE> ebpf-go:latest
```

### Kubernetes
See [ebpf-deployment](../performance_tests/kubernetes-deployments/ebpf-deployment/daemonset1.yaml). Requires the image to be pushed to an image registrar, such as Docker Hub.

