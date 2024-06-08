# All commands used for a test run

## Kubeadm
Run the scripts in [quick-kubeadm.md](./quick-kubeadm.md)

## Ingress
This script install the NGINX Ingress Controller and Ingress resource. Must be run twice, with a 10 second interval between.
```bash
kubectl apply -f ../kubernetes-deployments/ingress
```

## Jaeger
Run scripts in [quick-jaeger.md](./quick-jaeger.md)

### k6
Run scripts in [quick-k6.md](./quick-k6.md)

## Run Metrics Server
Not necessary, but usefull if one want to use the `kubectl top` command during tests.
```bash
kubectl apply -f ../kubernetes-deployments/metrics-server
```

## Apply the service mesh or eBPF program
Depends on the service deployed:

* **Istio (default, Merbridge and Ambient)**: [quick-istio.md](./quick-istio.md)
* **Linkerd**: [quick-linkerd.md](./quick-linkerd.md)
* **Traefik Mesh**: [quick-traefikmesh.md](./quick-traefikmesh.md)
* **Cilium**: [quick-cilium.md](./quick-cilium.md)
* **eBPF artifact**: ```kubectl apply -f ../kubernetes-deployments/ebpf-deployment```


## Database and HTTP Server
```bash
kubectl apply -f master-yamls/database
# Wait until it is running
kubectl apply -f ../kubernetes-deployments/http-server
```



## Test Run

### Run test commands
```bash
kubectl create configmap k6-scripts --from-file ../k6-scripts/<test.js>
python3 resource-scraper.py
# Update k6/test-run.yaml file spec
kubectl apply -f k6/
```

### Clean up
1. kubectl delete -f k6/test-run.yaml
2. Stop resource scraper
3. Move k6 files from worker node
4. Download Traces from Jaeger
5. Remove previous configmap
6. Restart the HTTP server and database deployment