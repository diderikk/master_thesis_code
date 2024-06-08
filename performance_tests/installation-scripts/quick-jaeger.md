# Quick Jaeger Setup

### cert-manager
```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.3/cert-manager.yaml
kubectl get pods --namespace cert-manager
```

### Operator
```bash
kubectl create namespace observability
kubectl create -f https://github.com/jaegertracing/jaeger-operator/releases/download/v1.53.0/jaeger-operator.yaml -n observability 
```

```bash
kubectl get deployment jaeger-operator -n observability
```


```yaml
cat <<EOF | kubectl apply -f -
apiVersion: jaegertracing.io/v1
kind: Jaeger
metadata:
  name: simplest
  namespace: observability
spec:
  ingress:
    ingressClassName: nginx
EOF
```