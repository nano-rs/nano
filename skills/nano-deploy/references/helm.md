# Kubernetes (Helm)

The `nano` Helm chart is the only Kubernetes path. The authority is the
product guide (nano.rs/docs → Kubernetes (Helm)). This page is the agent
procedure. It assumes the operator's cluster exists. You do not create or
resize clusters or node pools unless they ask.

## Step 0: preflight (read-only)

```bash
kubectl version            # server 1.28+ (1.30+ recommended)
helm version               # 3.14+ or 4
kubectl get storageclass   # a default class, or one named for ClickHouse
kubectl get gatewayclass   # a Gateway API implementation (Envoy Gateway on own hardware)
kubectl get crd | grep -E 'gateway.networking.k8s.io|cert-manager.io|clickhouse' || true
kubectl get nodes -L kubernetes.io/arch,nano.rs/pool -o wide
kubectl top nodes 2>/dev/null || echo "metrics-server missing (needed for the Vector HPA from 'standard' up)"
```

On x86-64, nodes need AVX2 for ClickHouse. From the `standard` preset up you
need an ingest node pool labelled and tainted `nano.rs/pool=ingest`, or
override `ingest.nodeSelector`/`ingest.tolerations`. Report gaps and stop.

## Step 1: choose the presets

- Sizing preset: the one `size.py --topology helm` printed
  (`values-small|standard|large|xlarge.yaml`).
- Exposure preset: `values-sovereign.yaml` (Envoy Gateway, own hardware),
  `values-gke.yaml`, `values-aws.yaml` or `values-azure.yaml`.
- HA: `clickhouse.replicas: 2` (about 2× the ClickHouse cost, Keeper ×3).
  Production also wants external PostgreSQL (`postgresql.mode: external`).
  Plan the shard count up front, because shards cannot be added by changing
  one value.

The presets ship inside the chart:
`helm pull oci://us-central1-docker.pkg.dev/nano-rs/charts/nano --version $V --untar`.

## Step 2: namespace and pull secret (mutating, secret)

```bash
kubectl create namespace nano --dry-run=client -o yaml | kubectl apply -f -
kubectl -n nano create secret docker-registry nano-registry \
  --docker-server=REGISTRY_HOST --docker-username=REGISTRY_USER \
  --docker-password="$(cat "$REGISTRY_CRED_FILE")" --dry-run=client -o yaml | kubectl apply -f -
```

The password is read inside the command substitution and is not echoed.
Never put it in a values file.

## Step 3: values (local files)

```bash
helm show values oci://us-central1-docker.pkg.dev/nano-rs/charts/nano --version $V > ./nano-deploy-work/helm/chart-values.yaml
python3 scripts/helm-values.py --chart-values ./nano-deploy-work/helm/chart-values.yaml \
  --enrollment "$ENROLLMENT_FILE" --base-url https://APP_FQDN \
  --app-host APP_FQDN --ingest-host INGEST_FQDN --pull-secret nano-registry \
  --issuer letsencrypt --storage-gi <from size.py> --hot-days <retention> \
  --out ./nano-deploy-work/helm
```

`values-site.yaml` can be reviewed and kept in the operator's config repo.
`values-licence.yaml` is secret: mode `0600`, never committed. Alternatively,
the operator manages the whole secret (`secrets.existingSecret`, for example
External Secrets or Vault) with the keys listed in the product guide.

For about 10–15 GB/day, the Kubernetes guide's "Example: about 12.5 GB/day"
layers `values-small.yaml` with larger ClickHouse resources and 1500Gi of
storage, plus an HA file (`clickhouse.replicas: 2`, Keeper 3, two replicas of
the app services, `ingest.edge.hecAcks: false`, external PostgreSQL). Use
those values as they are. The chart refuses some combinations at render
time.

Pin images by digest from the release lock:
`deploy/helm/nano/scripts/values-from-lock.sh images.enterprise.customer.lock > images-values.yaml`
(the customer lock ships in the enterprise compose bundle and lists the same
digests in the customer repository).

## Step 4: render and diff (read-only)

```bash
helm template nano oci://us-central1-docker.pkg.dev/nano-rs/charts/nano --version $V -n nano \
  -f values-standard.yaml -f values-sovereign.yaml -f images-values.yaml \
  -f ./nano-deploy-work/helm/values-site.yaml -f ./nano-deploy-work/helm/values-licence.yaml > /dev/null && echo RENDER-OK
```

A render error, such as a Keeper-count refusal or a Vector buffer that does
not fit, is a hard stop. Fix the value; never edit chart templates.

## Step 5: install (mutating)

```bash
helm upgrade --install nano oci://us-central1-docker.pkg.dev/nano-rs/charts/nano --version $V -n nano \
  -f values-standard.yaml -f values-sovereign.yaml -f images-values.yaml \
  -f ./nano-deploy-work/helm/values-site.yaml -f ./nano-deploy-work/helm/values-licence.yaml
kubectl -n nano get pods -w
kubectl -n nano logs -f job/nano-migrate-r1
```

`upgrade --install` is idempotent. Point DNS for both hostnames at the two
Gateways (`kubectl -n nano get gateway`).

## Step 6: back up the generated secret

The chart generates `nano-secrets` once. Losing `encryption_key` makes every
stored credential unrecoverable. Ask the operator where to store a copy
(their secret manager), then export it straight there. Do not print it:

```bash
kubectl -n nano get secret nano-secrets -o yaml > "$OPERATOR_SECRET_PATH" && chmod 600 "$OPERATOR_SECRET_PATH"
```

## Step 7: verify

```bash
helm test nano -n nano
curl -fsS https://APP_FQDN/api/health
```

The first admin is created on the one-time setup page in the UI. Ask the
operator to do it, or use `POST /api/setup/initialize` with a password file
they provide. Then run the smoke test from a machine that can reach both
hostnames, with the admin credential file there:

```bash
python3 scripts/smoke-test.py --app-url https://APP_FQDN --ingest-url https://INGEST_FQDN --creds ./admin-creds.env
```

Upgrades: `helm upgrade` with the same values and a new `--version`. Back up
first ([operate.md](operate.md#kubernetes)).
