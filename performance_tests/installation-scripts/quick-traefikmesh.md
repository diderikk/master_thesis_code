# Quick Traefik Mesh

## Install Helm

```bash
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
sudo apt-get install apt-transport-https --yes
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm
```

## Install

```bash
helm repo add traefik https://traefik.github.io/charts
helm repo update
helm install traefik-mesh traefik/traefik-mesh --set metrics.deploy=false --set tracing.deploy=false
```

### Usage
Usage, use proxy by changing Kubernetes DNS service endpoint server.test.svc.cluster.local to server.test.traefik.mesh
replacing `svc.cluster.local` with `traefik.mesh`

Changed k6-testrun API_ENDPOINT environment variable. Did not work for HTTP server to database. Not using tracing