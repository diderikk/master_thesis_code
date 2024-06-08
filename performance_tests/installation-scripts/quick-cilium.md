# Quick Cilium

## Install

### Worker node config
This is used for the SPIRE server configured by the Cilium installation. The worker node to run the command, is the worker node specified in the file [../kubernetes-deployments/cilium/pv.yaml](../kubernetes-deployments/cilium/pv.yaml)
```bash
mkdir /tmp/cilium
chmod 777 /tmp/cilium
```

### Add PV
```bash
kubectl apply -f cilium
```

### Install Cilium CLI
```bash
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
CLI_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
```

### Add a IpSec Key used by Cilium for encryption
```bash
kubectl create -n kube-system secret generic cilium-ipsec-keys \
    --from-literal=keys="3+ rfc4106(gcm(aes)) $(echo $(dd if=/dev/urandom count=20 bs=1 2> /dev/null | xxd -p -c 64)) 128"
```

### Install Cilium CNI and Service mesh
```bash
cilium install --version 1.15.3 --set envoyConfig.enabled=true --set authentication.mutual.spire.enabled=true --set authentication.mutual.spire.install.enabled=true --set authentication.mutual.spire.install.server.dataStorage.enabled=true 

cilium upgrade --version 1.15.3 --set envoyConfig.enabled=true --set authentication.mutual.spire.enabled=true --set authentication.mutual.spire.install.enabled=true --set authentication.mutual.spire.install.server.dataStorage.enabled=true  --set encryption.enabled=true --set encryption.type=ipsec
```

## Hubble
```bash
cilium hubble enable --ui
```

```bash
HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
HUBBLE_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then HUBBLE_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
sha256sum --check hubble-linux-${HUBBLE_ARCH}.tar.gz.sha256sum
sudo tar xzvfC hubble-linux-${HUBBLE_ARCH}.tar.gz /usr/local/bin
rm hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
```

```bash
cilium hubble port-forward&
hubble status
hubble observe
```
