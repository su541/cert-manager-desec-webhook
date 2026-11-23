<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>

# ACME webhook for desec.io DNS API

This solver can be used with [desec.io](https://desec.io) DNS API. The documentation
of the API can be found [here](https://desec.readthedocs.io/en/latest/)

## Requirements
- [helm](https://helm.sh/) >= v3.8.0 (OCI support)
- [kubernetes](https://kubernetes.io/)
- [cert-manager](https://cert-manager.io/)
- for development: [go](https://golang.org) >= 1.26

## Installation

### Using the public helm chart (OCI)
```bash
helm install desec-webhook -n cert-manager \
  oci://ghcr.io/su541/helm/cert-manager-desec-webhook --version <version>
```
Available versions are listed on the [releases page](https://github.com/su541/cert-manager-desec-webhook/releases).
The image tag defaults to the chart's `appVersion`, so chart and image always match.

### Using helm from local checkout
```bash
helm install desec-webhook -n cert-manager deploy/desec-webhook
```

## Uninstallation
```bash
helm uninstall desec-webhook -n cert-manager
```

## Creating an issuer

Create a secret containing the credentials
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: desec-io-token
  namespace: cert-manager
type: Opaque
data:
  token: your-key-base64-encoded
```

```shell
kubectl create secret generic desec-io-token --from-literal "token=<your token>" --namespace cert-manager
```

The webhook may only read the secrets listed in `secretName` (values.yaml) in the
namespace it is installed in. With a `ClusterIssuer`, put the secret into that
namespace (usually `cert-manager`).

Create a 'ClusterIssuer' or 'Issuer' resource as the following:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    email: mail@example.com

    privateKeySecretRef:
      name: letsencrypt-staging

    solvers:
      - dns01:
          webhook:
            config:
              apiKeySecretRef:
                key: token
                name: desec-io-token
            groupName: de.su541.acme
            solverName: desec
```

## Create a manual certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-cert
  namespace: cert-manager
spec:
  commonName: example.com
  dnsNames:
    - example.com
  issuerRef:
    name: letsencrypt-staging
    kind: ClusterIssuer
  secretName: example-cert
```

## Using cert-manager with traefik ingress
```yaml

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: bitwarden
  namespace: utils
  labels:
    app: bitwarden
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-staging
    kubernetes.io/ingress.class: traefik
    traefik.ingress.kubernetes.io/rewrite-target: /$1
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: 'true'
spec:
  tls:
    - hosts:
        - bitwarden.acme.example.com
      secretName: bitwarden-crt
  rules:
    - host: bitwarden.acme.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: bitwarden
                port:
                  number: 80

```

## Development

### Unit tests
```bash
make test
```
The unit tests run against an in-memory fake of the deSEC API and a fake
Kubernetes client. They need no credentials.

### Conformance tests
All DNS providers **must** pass the cert-manager DNS01 conformance suite. It
runs against the real deSEC API and needs a deSEC domain and an API token:

```bash
export DESEC_TOKEN=<your token>
TEST_ZONE_NAME=example.com. make test-conformance
```
The token is only written to a temporary directory during the test.

## Releases

Versioning follows [Semantic Versioning](https://semver.org/) and is derived
from [Conventional Commits](https://www.conventionalcommits.org/) by
[release-please](https://github.com/googleapis/release-please):

| Commit / PR title | Version bump |
|---|---|
| `fix: ...` | patch |
| `feat: ...` | minor |
| `feat!: ...` or footer `BREAKING CHANGE: ...` | major |
| `docs:`, `chore:`, `ci:`, `test:`, `refactor:` | none |

PRs are squash-merged, so the **PR title** must be a Conventional Commit (checked by CI).
release-please keeps a release PR open that collects the changes. Merging it
creates the tag `vX.Y.Z`, the GitHub release and `CHANGELOG.md`, and publishes

- the image `ghcr.io/su541/cert-manager-desec-webhook` with the tags `X.Y.Z`, `X.Y`, `X` and `latest` (cosign-signed)
- the chart `oci://ghcr.io/su541/helm/cert-manager-desec-webhook` with version `X.Y.Z`

Every push to `master` additionally publishes the image tags `master` and `sha-<commit>`.
