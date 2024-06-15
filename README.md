# Master Thesis reseach code  
This repository contains all the files and modules necessary for completing the master's thesis.   
Made by: [Diderik Kramer](https://github.com/diderikk)

## Project structure
* **ebpf_artifact**: Consists of four Golang modules implementing four eBPF programs that each mimic a service mesh characteristic. The eBPF programs have only been compiled and deployed using kernel version `Linux 6.5.0-35-generic x86_64`.
* **http_server_impl**: Consist of the HTTP server implementation using Phoenix/Elixir.
* **performance_tests**: Consists of all the scripts used to perform the performance tests and the plots representing the metrics extracted during the tests.

## Test environment
The Kubernetes cluster setup consisted of four Proxmox VMs. For reference, the Proxmox operating system was run on a local machine with an Intel i7-12700H CPU (20 threads) and 32 GB RAM connected to a home network using an Ethernet cable.

* **Master node**: 4 vCPUs, 4 GiB RAM, 64 GB Storage, Ubuntu Server 22.04 OS
* **Worker 1 node**: 4 vCPUs, 4 GiB RAM, 64 GB Storage, Ubuntu Server 22.04 OS
* **Worker 2 node**: 6 vCPUs, 8 GiB RAM, 64 GB Storage, Ubuntu Server 22.04 OS
* **Worker 3 node**: 4 vCPUs, 4 GiB RAM, 64 GB Storage, Ubuntu Server 22.04 OS