# Kubernetes (Helm)

The `nano` Helm chart is the only Kubernetes path. The authority is the
product guide (nano.rs/docs → Kubernetes (Helm)). This page is the agent
procedure. It assumes the operator's cluster exists. You do not create or
resize clusters or node pools unless they ask. With no cluster yet, propose
one from [cloud-aws.md](cloud-aws.md#amazon-eks-for-the-helm-chart) (EKS),
[cloud-gcp.md](cloud-gcp.md#gke-for-the-helm-chart) (GKE) or
[cloud-azure.md](cloud-azure.md#aks-for-the-helm-chart) (AKS), and create it
only after the operator approves.

The chart lives in the customer registry repository, the one the Self-run
pull credential can read:

```bash
export CHART=oci://us-central1-docker.pkg.dev/nano-rs/nanosiem-customer/charts/nano
# The current release (or the version the operator chose):
export V=$(curl -fsS https://api.nano.rs/api/releases/latest | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')
```

(`.../nano-rs/charts/nano` is not readable with a customer credential: 403.)

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

EKS specifics (each is a hard stop; [cloud-aws.md](cloud-aws.md#amazon-eks-for-the-helm-chart)):
no default StorageClass until the EBS CSI add-on and a default gp3 class
exist; `values-aws.yaml` needs the AWS Load Balancer Controller (v2.13+, Gateway
API feature gate on), the Gateway API CRDs, the controller's gateway CRDs, a
GatewayClass `aws-alb`, and ACM certificates for both hostnames.

On x86-64, nodes need AVX2 for ClickHouse. From the `standard` preset up you
need an ingest node pool labelled and tainted `nano.rs/pool=ingest`, or
override `ingest.nodeSelector`/`ingest.tolerations`. Report gaps and stop.

External PostgreSQL (`postgresql.mode: external`, every production install):
check it before `helm install`, read-only. The probe needs PostgreSQL 16+,
that the nano user can CREATE in schema `public` (Azure flexible server gives
`public` to `azure_pg_admin`), and that it can create `pg_trgm`, `pgcrypto` and
`uuid-ossp`; each CREATE EXTENSION is rolled back. Run it from inside the cluster (it reaches
private-IP databases) once the namespace and the password Secret exist (Step 2):

```bash
python3 -I scripts/pg-preflight.py kube --namespace nano --host DB_HOST \
  --user nanosiem --database nanosiem --password-secret nano-postgres --password-key password
# or with postgresql.external.urlSecret:
python3 -I scripts/pg-preflight.py kube --namespace nano --url-secret NAME --url-key database_url
```

From a machine with `psql` and network access, `pg-preflight.py local --host
DB_HOST` uses the operator's `PGPASSWORD` / `~/.pgpass`. `POSTGRES-NOT-READY`
is a hard stop; it prints the fix (the per-cloud details are in
[cloud-aws.md](cloud-aws.md#managed-postgresql-rds), [cloud-gcp.md](cloud-gcp.md#managed-postgresql-cloud-sql)
and [cloud-azure.md](cloud-azure.md#managed-postgresql-azure-flexible-server)). The
migrator runs the same check before it applies anything (2.0.11+; the
schema check from 2.0.12), so a missed one fails `nano-migrate-r1` with the
same message instead of a half-applied schema. With 2.0.11 and the skill
before 2.0.12, a missing `CREATE` on `public` passed both checks and failed
the first migration with `permission denied for schema public`
([known-issues.md](known-issues.md)).

After a failed first migration is fixed, the failed `nano-migrate-r1` pods
stay behind and keep `k8s-health.py` at `WARN jobs` until the next `helm
upgrade` replaces the Job. Once the install is healthy, delete them:
`kubectl -n nano delete pod -l job-name=nano-migrate-r1 --field-selector=status.phase=Failed`.

## Step 1: choose the presets

- Sizing preset: the one `size.py --topology helm` printed
  (`values-small|standard|large|xlarge.yaml`).
- Exposure preset: `values-sovereign.yaml` (Envoy Gateway, own hardware),
  `values-gke.yaml`, `values-aws.yaml` or `values-azure.yaml`.
- HA: `clickhouse.replicas: 2` (about 2× the ClickHouse cost, Keeper ×3).
  Production also wants external PostgreSQL (`postgresql.mode: external`).
  Plan the shard count up front, because shards cannot be added by changing
  one value.

The presets ship inside the chart, with the release's customer image lock
(`images.enterprise.customer.lock`) and the digest pins rendered from it
(`values-customer-images.yaml`):
`helm pull "$CHART" --version $V --untar` (creates `./nano/`).

## Step 2: namespace and pull secret (mutating, secret)

```bash
kubectl create namespace nano --dry-run=client -o yaml | kubectl apply -f -
# Build the dockerconfigjson in a 0600 file: the password is read from the
# credential file by python and never appears in any process's arguments.
( umask 077; python3 -I - "$REGISTRY_CRED_FILE" REGISTRY_HOST REGISTRY_USER \
    > ./nano-deploy-work/dockerconfig.json <<'PY'
import base64, json, sys
cred, host, user = sys.argv[1:4]
password = open(cred, encoding="utf-8").read().rstrip("\n")
auth = base64.b64encode(f"{user}:{password}".encode()).decode()
print(json.dumps({"auths": {host: {"username": user, "password": password, "auth": auth}}},
                 separators=(",", ":")))
PY
)
kubectl -n nano create secret generic nano-registry \
  --type=kubernetes.io/dockerconfigjson \
  --from-file=.dockerconfigjson=./nano-deploy-work/dockerconfig.json \
  --dry-run=client -o yaml | kubectl apply --server-side --force-conflicts -f -
rm -f ./nano-deploy-work/dockerconfig.json
```

Do not use `kubectl create secret docker-registry --docker-password=...`:
the password lands on kubectl's command line, visible in `ps` and shell
history. Never put it in a values file. The registry credential refresh
CronJob merges into this Secret's `.dockerconfigjson`, so keep the type
`kubernetes.io/dockerconfigjson`. Apply Secrets with `--server-side`: a
client-side `kubectl apply` also copies the whole Secret, credential included,
into the `kubectl.kubernetes.io/last-applied-configuration` annotation, where a
stale copy can linger after the value rotates (the 2.0.11 refresh job removes
it). `--force-conflicts` is needed on a re-run because the refresh CronJob
owns `.dockerconfigjson` once it has run.

External PostgreSQL password (when `postgresql.mode: external`), also from a
file and never on a command line:

```bash
kubectl -n nano create secret generic nano-postgres \
  --from-file=password="$PG_PASSWORD_FILE" --dry-run=client -o yaml | kubectl apply --server-side -f -
```

The file must hold only the URL-safe password, with no trailing newline
(`printf %s`); it is interpolated into `DATABASE_URL`.

## Step 3: values (local files)

```bash
helm show values "$CHART" --version $V > ./nano-deploy-work/helm/chart-values.yaml
python3 scripts/helm-values.py --chart-values ./nano-deploy-work/helm/chart-values.yaml \
  --enrollment "$ENROLLMENT_FILE" --base-url https://APP_FQDN \
  --app-host APP_FQDN --ingest-host INGEST_FQDN --pull-secret nano-registry \
  --issuer letsencrypt --storage-gi <from size.py> --hot-days <retention> \
  --out ./nano-deploy-work/helm
```

`--issuer` is for cert-manager TLS only. With a cloud preset that brings its
own TLS (`values-aws.yaml`: ACM, `values-gke.yaml`: Certificate Manager), omit
it and put the certificate references in `values-site.yaml`, e.g.
`tls: {aws: {appCertificateArn: ..., ingestCertificateArn: ...}}`. Never set
`tls.mode` in a site file layered after the cloud preset: the last file wins.

`values-site.yaml` can be reviewed and kept in the operator's config repo.
`values-licence.yaml` is secret: mode `0600`, never committed. Alternatively,
the operator manages the whole secret (`secrets.existingSecret`, for example
External Secrets or Vault) with the keys listed in the product guide.
The product guide passes the token with `--set-file
secrets.licenseToken=./license-token.txt` instead; both set the same key. An
upgrade that leaves the token out keeps the one already installed (the chart
reuses every key of the existing `nano-secrets`), so the guide's upgrade
command omits it safely. Pass a new token only to replace it.

For about 10–15 GB/day, the Kubernetes guide's "Example: about 12.5 GB/day"
layers `values-small.yaml` with larger ClickHouse resources and 1500Gi of
storage, plus an HA file (`clickhouse.replicas: 2`, Keeper 3, two replicas of
the app services, `ingest.edge.hecAcks: false`, external PostgreSQL). Use
those values as they are. The chart refuses some combinations at render
time.

Pin images by digest: use `nano/values-customer-images.yaml` from the pulled
chart as it is (regenerate only if asked:
`bash nano/scripts/values-from-lock.sh nano/images.enterprise.customer.lock > nano/values-customer-images.yaml`).

The Self-run pull credential lasts one hour. The chart's
`registryCredentialRefresh` CronJob (on by default when `nano.license.url`,
`nano.deploymentId` and `global.imagePullSecrets` are set and no
`global.imageRegistry` mirror is used) re-mints it every 20 minutes with the
enrollment token and patches `nano-registry`. Without it, any pod scheduled
after the first hour fails with ImagePullBackOff. Check it after install:
`kubectl -n nano create job --from=cronjob/nano-registry-cred-refresh refresh-now`.

## Step 4: render and diff (read-only)

```bash
helm template nano ./nano -n nano \
  -f nano/values-customer-images.yaml -f nano/values-standard.yaml -f nano/values-sovereign.yaml \
  -f ./nano-deploy-work/helm/values-site.yaml -f ./nano-deploy-work/helm/values-licence.yaml > /dev/null && echo RENDER-OK
```

A render error, such as a Keeper-count refusal or a Vector buffer that does
not fit, is a hard stop. Fix the value; never edit chart templates.

## Step 5: install (mutating)

```bash
helm upgrade --install nano ./nano -n nano --wait --timeout 20m \
  -f nano/values-customer-images.yaml -f nano/values-standard.yaml -f nano/values-sovereign.yaml \
  -f ./nano-deploy-work/helm/values-site.yaml -f ./nano-deploy-work/helm/values-licence.yaml
kubectl -n nano get pods -w
kubectl -n nano logs -f job/nano-migrate-r1
```

The first migration can take 10+ minutes against a remote managed PostgreSQL.
Keep `--timeout` at or below `migrations.dependentProgressDeadlineSeconds`
(1800 s from 2.0.11): use `--wait --timeout 30m` there. If the install still
fails, read the migration Job's log first, fix the cause, and run the same
`helm upgrade --install` again ([known-issues.md](known-issues.md)).

Before go-live, confirm the cluster ENFORCES NetworkPolicy (GKE Dataplane V2,
EKS VPC CNI network policy agent, set at creation in
[cloud-aws.md](cloud-aws.md#amazon-eks-for-the-helm-chart); AKS
`--network-policy`): the chart's policy protects Vector's in-cluster ports
only where it is enforced. Check from another namespace (prints `000` when
enforced, `401` when not; the pod ends normally either way):

```bash
kubectl run np-test -n default --rm -i --image=curlimages/curl:8.12.1 --restart=Never --command -- \
  sh -c 'curl -s -m 5 -o /dev/null -w "%{http_code}\n" http://nano-vector-internal.nano.svc.cluster.local:4318/v1/logs; true'
```

Vector's metrics port (9598, no credential, read-only counters) stays open
to every pod on 2.0.11 even with enforcement; from 2.0.12 only to nano's
namespace (`vector.metrics.networkPolicyFrom` adds a scraper's namespace).

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
python3 -I scripts/k8s-health.py --namespace nano
curl -fsS https://APP_FQDN/api/health
```

`helm test` does not catch a Vector that never starts; `k8s-health.py` does.

The first admin is created on the one-time setup page in the UI. Ask the
operator to do it, or use `POST /api/setup/initialize` with a password file
they provide; the JSON body is `{"email": "...", "name": "...", "password": "..."}`
(build it from the file with python, never on the command line). Both need the setup token, key `setup_token` in the chart's
secret (`nano-secrets`, or your `existingSecret`). The operator reads it on
their machine (do not print it yourself):
`kubectl -n nano get secret nano-secrets -o jsonpath='{.data.setup_token}' | base64 -d`.
The API call sends it as `Authorization: Bearer <token>`, read from a file.
Once the admin exists the token is no longer needed. Then run the smoke test from a machine that can reach both
hostnames, with the admin credential file there:

```bash
python3 scripts/smoke-test.py --app-url https://APP_FQDN --ingest-url https://INGEST_FQDN --creds ./admin-creds.env
```

Upgrades: pull the NEW chart over the old one first, because
`nano/values-customer-images.yaml` pins the digests of the chart it came with
(reusing the old `./nano` silently keeps the old images), then upgrade from it
with exactly the install's `-f` files in the same order (dropping the HA or
cloud file silently changes the install). Back up first
([operate.md](operate.md#kubernetes)).

```bash
export V=<new version>
rm -rf nano && helm pull "$CHART" --version $V --untar
helm upgrade nano ./nano -n nano --wait --timeout 20m \
  -f nano/values-customer-images.yaml -f nano/values-standard.yaml -f nano/values-sovereign.yaml \
  -f ./nano-deploy-work/helm/values-site.yaml -f ./nano-deploy-work/helm/values-licence.yaml
```

A failed upgrade or install migration: follow the product guide's
"Upgrade recovery" (nano.rs/docs/getting-started/kubernetes#upgrade-recovery).
In short: read `kubectl -n nano logs job/nano-migrate-r<N>` and, when
ClickHouse is down, `kubectl -n nano logs <clickhouse pod> --previous`. From
2.0.10 a pre-upgrade hook (`nano-ch-config-heal-r<N>`) pushes the new
ClickHouse settings to a ClickHouse that does not answer, so the fix is: correct
the value, rerun the same `helm upgrade --wait --timeout 20m`. Report the cause to the
operator; never edit chart templates or delete the release.
