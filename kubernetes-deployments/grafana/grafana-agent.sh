curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
sudo apt-get install apt-transport-https --yes
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm

helm repo add grafana https://grafana.github.io/helm-charts &&
  helm repo update &&
  helm upgrade --install --atomic --timeout 300s grafana-k8s-monitoring grafana/k8s-monitoring \
    --namespace "default" --create-namespace --values - <<EOF
cluster:
  name: my-cluster
externalServices:
  prometheus:
    host: https://prometheus-prod-39-prod-eu-north-0.grafana.net
    basicAuth:
      username: "1437173"
      password: glc_eyJvIjoiMTA1OTM1MSIsIm4iOiJzdGFjay04NjI2OTctaW50ZWdyYXRpb24taW5pdGlhbC1pbml0aWFsIiwiayI6IkYzVThtWlBtVU02NmdMZjI3cDNROEU2MSIsIm0iOnsiciI6InByb2QtZXUtbm9ydGgtMCJ9fQ==
  loki:
    host: https://logs-prod-025.grafana.net
    basicAuth:
      username: "817577"
      password: glc_eyJvIjoiMTA1OTM1MSIsIm4iOiJzdGFjay04NjI2OTctaW50ZWdyYXRpb24taW5pdGlhbC1pbml0aWFsIiwiayI6IkYzVThtWlBtVU02NmdMZjI3cDNROEU2MSIsIm0iOnsiciI6InByb2QtZXUtbm9ydGgtMCJ9fQ==
  tempo:
    host: https://tempo-prod-18-prod-eu-north-0.grafana.net:443
    basicAuth:
      username: "814795"
      password: glc_eyJvIjoiMTA1OTM1MSIsIm4iOiJzdGFjay04NjI2OTctaW50ZWdyYXRpb24taW5pdGlhbC1pbml0aWFsIiwiayI6IkYzVThtWlBtVU02NmdMZjI3cDNROEU2MSIsIm0iOnsiciI6InByb2QtZXUtbm9ydGgtMCJ9fQ==
metrics:
  enabled: true
  cost:
    enabled: true
  node-exporter:
    enabled: true
logs:
  enabled: true
  pod_logs:
    enabled: true
  cluster_events:
    enabled: true
traces:
  enabled: true
opencost:
  enabled: true
  opencost:
    exporter:
      defaultClusterId: my-cluster
    prometheus:
      external:
        url: https://prometheus-prod-39-prod-eu-north-0.grafana.net/api/prom
kube-state-metrics:
  enabled: true
prometheus-node-exporter:
  enabled: true
prometheus-operator-crds:
  enabled: true
grafana-agent: {}
grafana-agent-logs: {}
EOF