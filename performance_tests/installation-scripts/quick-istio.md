# Quick Istio

## CLI Tool

```bash
curl -L https://istio.io/downloadIstio | sh -
export PATH="$PATH:/home/node/istio-1.22.0/bin"
istioctl x precheck
```

## Install Istiod

```bash
istioctl install -y
```

Add the following label to all pods that one want to have attach a sidecar to sidecar.istio.io/inject: "true".

### Get Istio-proxy logs
```bash
kubectl logs <pod-name> -c istio-proxy

2024-04-02T11:23:38.171932Z	info	cache	generated new workload certificate	latency=64.869955ms ttl=23h59m59.828069729s
2024-04-02T11:23:38.171950Z	info	cache	Root cert has changed, start rotating root cert
2024-04-02T11:23:38.171961Z	info	ads	XDS: Incremental Pushing ConnectedEndpoints:0 Version:
2024-04-02T11:23:38.171984Z	info	cache	returned workload trust anchor from cache	ttl=23h59m59.82801609s
2024-04-02T11:23:40.155161Z	info	ads	ADS: new connection for node:simple-59dfdfc487-6645n.default-1
2024-04-02T11:23:40.155199Z	info	cache	returned workload certificate from cache	ttl=23h59m57.844801648s
2024-04-02T11:23:40.155378Z	info	ads	SDS: PUSH request for node:simple-59dfdfc487-6645n.default resources:1 size:4.0kB resource:default
2024-04-02T11:23:40.156014Z	info	ads	ADS: new connection for node:simple-59dfdfc487-6645n.default-2
2024-04-02T11:23:40.156204Z	info	cache	returned workload trust anchor from cache	ttl=23h59m57.843796584s
2024-04-02T11:23:40.156345Z	info	ads	SDS: PUSH request for node:simple-59dfdfc487-6645n.default resources:1 size:1.1kB resource:ROOTCA
2024-04-02T11:23:40.539467Z	info	Readiness succeeded in 4.455876551s
2024-04-02T11:23:40.539652Z	info	Envoy proxy is ready
```

### Kiali
```bash
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/addons/kiali.yaml
```

### Merbrige

### Install
```bash
kubectl apply -f https://raw.githubusercontent.com/merbridge/merbridge/main/deploy/all-in-one.yaml
```

#### Delete
```bash
kubectl delete -f https://raw.githubusercontent.com/merbridge/merbridge/main/deploy/all-in-one.yaml
```

## Ambient

### Install
```bash
istioctl install --set profile=ambient
kubectl label namespace default istio.io/dataplane-mode=ambient # All relevant pods run in the default namespace (Database, HTTP server and HTTP client)
```

[Adding Pod to Ambient mesh](https://istio.io/latest/docs/ambient/usage/add-workloads/)
Add the following label to all pods that one want to join the ambient mesh istio.io/dataplane-mode: "ambient"


## Purge
```bash
istioctl uninstall --purge
kubectl delete namespace istio-system
```
