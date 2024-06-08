# Quick Linkerd

## Install
```bash
curl --proto '=https' --tlsv1.2 -sSfL https://run.linkerd.io/install-edge | sh
export PATH=$PATH:/home/node/.linkerd2/bin

linkerd check --pre
```

```bash
linkerd install --crds | kubectl apply -f -
linkerd install | kubectl apply -f -
linkerd check
```

### Injection

"Linkerd automatically adds the data plane proxy to pods when the linkerd.io/inject: enabled annotation is present on a namespace or any workloads, such as deployments or pods. This is known as "proxy injection"." [Proxy Injection](https://linkerd.io/2.15/features/proxy-injection/)

## Viz
```bash
linkerd viz install | kubectl apply -f - # install the on-cluster metrics stack
linkerd check
linkerd viz dashboard &
```

## Delete
```bash
linkerd uninstall | kubectl delete -f -
kubectl delete namespace linkerd
```