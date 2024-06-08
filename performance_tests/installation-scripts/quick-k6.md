# Quick K6

## Install metrics server

## Install operator
```bash
curl https://raw.githubusercontent.com/grafana/k6-operator/main/bundle.yaml | kubectl apply -f -
kubectl get pods -n k6-operator-system
```

## Configure PV in worker node
```bash
sudo mkdir /tmp/tests
sudo chmod 777 /tmp/tests
```