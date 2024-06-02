# TODO

## Load balancer

* Possible implementation of and integration with Istio's Virtual Service, for canary deployments

### TODO LB

* /proc/net/tcp, shows that port 179 is used for BGP connection for route traffic over, could be used together with a BPF_PROG_TYPE_SK_SKB in order to route incomming sockets to correct sockets: [Attach eBPF sockops program to a specific container cgroup](https://stackoverflow.com/questions/76350203/attach-ebpf-sockops-program-to-a-specific-container-cgroup), [eBPF sockops samples](https://github.com/zachidan/ebpf-sockops/blob/master/README.md): THIS WON'T WORK SINCE THEY ONLY RECEIVE A COPY OF THE PACKET, THE ORIGINAL PACKET IS STILL SENT TO THE CORRECT INTERFACE.
* Test TC with Calico's virtual interfaces
* Test TC with Flannel
* Test XDP with NodePort

https://www.cyberciti.biz/faq/howto-upgrading-the-ubuntu-linux-kernel/

## Network Policy

1. Check if possible to integrate with the existing Network Policy, and argue that eBPF

## Bandwidth management

1. Store all from and to addresses (IP address and port) in a map. Perhaps from and to addresses as keys, and number of interactions as value. Userspace program can reset counter every 5-10 seconds. From this we can set a max limit of the counter, and if the counter exceed this, packets are aborted.

## Observability

1. Select the metrics and variable that want to be observed.
2. Should use BPF_MAP_TYPE_RINGBUF to send observed data to userspace
    1. If latency is required, a TC deployment can be made separately, which points to the same BPF_MAP_TYPE_RINGBUF map.

## Deployment

Dockerfile
