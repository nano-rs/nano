# Google Cloud

Cloud specifics for [cloud-vm.md](cloud-vm.md) (VMs) and, at the end, for a
GKE cluster for the Helm chart ([GKE](#gke-for-the-helm-chart)). Ask before
every mutating step. The commands use the operator's own `gcloud` session.

```bash
export PROJECT=<project id> REGION=us-central1 NAME=<cluster name>
gcloud config list                     # show account and project, ask before going on
export CLOUDSDK_CORE_PROJECT=$PROJECT  # this shell only; never `gcloud config set project`
```

`gcloud config set project` changes the operator's global default for every
other terminal; the environment variable scopes it to this session.

Label every resource `--labels nano-deployment=$NAME` where the command takes
it. `gcloud sql instances create` and `gcloud compute addresses create` have
no label flag in GA gcloud (checked on 564): label those through the REST API
(below).

## Instance and disk choices

`plan.py --cloud gcp` picks from these families (catalog
`scripts/cloud-catalog.json`, us-central1 on-demand prices as of 2026-11-10;
six prices were read directly, the rest are derived from per-vCPU and per-GiB
rates that reproduce the read prices, and the plan lists them as unverified):

| Role | Family | Disk |
|---|---|---|
| ClickHouse | `n2-highmem` (8 GiB per vCPU) | `pd-ssd` (performance scales with size) |
| App | `c3-standard` | 100 GiB `pd-balanced` boot disk |
| PostgreSQL + Keeper (+ etcd, Sentinel) | `n2-standard` | `pd-ssd` |
| Ingest | `c3-standard` | `pd-balanced` data disk for Docker and Vector buffers |

`c3-highmem` with Hyperdisk Balanced is a good alternative for ClickHouse when
its sizes (4, 8, 22, 44 vCPU) fit the plan; Hyperdisk Balanced includes 3,000
IOPS and 140 MiB/s and bills above that. Local SSD is left out: it needs
`-lssd` shapes and the planner does not price them.

## Network: one VPC, three zones

GCP subnets are regional, so one subnet holds every VM; the plan's addresses
(`10.40.1.x`, `10.40.2.x`, `10.40.3.x`) still map to zones a/b/c.

```bash
gcloud compute networks create $NAME-vpc --subnet-mode=custom
gcloud compute networks subnets create $NAME-private --network $NAME-vpc --region $REGION \
  --range 10.40.0.0/21 --enable-private-ip-google-access
gcloud compute routers create $NAME-router --network $NAME-vpc --region $REGION
gcloud compute routers nats create $NAME-nat --router $NAME-router --region $REGION \
  --auto-allocate-nat-external-ips --nat-all-subnet-ip-ranges
```

Cloud NAT gives the VMs egress without public IPs (registry, `api.nano.rs`,
platform feeds, Ubuntu and Docker repositories). Private Google Access keeps
Cloud Storage traffic internal. Operator access: IAP TCP forwarding for SSH
(allow `35.235.240.0/20` to port 22) or a bastion.

## Firewall rules: network tags

Tag each VM with the group of every role it runs: `nano-app`, `nano-ingest`,
`nano-control`, `nano-clickhouse` (co-located ingest VMs get both
`nano-clickhouse` and `nano-ingest`). The load balancers' traffic and health
checks come from Google's ranges `130.211.0.0/22` and `35.191.0.0/16`. The
rules come from the renderer's port matrix:

<!-- BEGIN plan.py --port-matrix (generated; do not edit) -->
| Port | Key | On | Allow from | When |
|---|---|---|---|---|
| 80/tcp | `app` | app hosts | app load balancer | always |
| 3000/tcp | `api_internal` | app hosts | ingest hosts, the monitoring host | always (monitoring: with a monitoring host) |
| 80/tcp | `ingest` | ingest hosts | ingest load balancer, app hosts | always |
| 8687/tcp | `vector_tap` | ingest hosts | app hosts | always |
| 5432/tcp | `postgres` | PostgreSQL hosts | app hosts, ClickHouse hosts, PostgreSQL hosts | always |
| 8123/tcp | `clickhouse_http` | ClickHouse hosts | app hosts, ingest hosts, ClickHouse hosts | always |
| 9000/tcp | `clickhouse_native` | ClickHouse hosts | app hosts, ingest hosts, ClickHouse hosts | always |
| 9009/tcp | `clickhouse_interserver` | ClickHouse hosts | ClickHouse hosts | always |
| 9363/tcp | `clickhouse_metrics` | ClickHouse hosts | app hosts, the monitoring host | always |
| 9181/tcp | `keeper_client` | Keeper hosts (= PostgreSQL hosts) | app hosts, ClickHouse hosts, Keeper hosts (= PostgreSQL hosts) | always |
| 9234/tcp | `keeper_raft` | Keeper hosts (= PostgreSQL hosts) | Keeper hosts (= PostgreSQL hosts) | always |
| 3030/tcp | `grafana` | the monitoring host | management CIDR | monitoring host |
| 9090/tcp | `prometheus` | the monitoring host | the monitoring host | monitoring host (loopback only: never open it) |
| 9100/tcp | `node_exporter` | app hosts | the monitoring host | monitoring host |
| 8405/tcp | `clickhouse_proxy_metrics` | app hosts | the monitoring host | monitoring host |
| 8406/tcp | `ingest_proxy_metrics` | app hosts | the monitoring host | monitoring host |
| 8408/tcp | `postgres_router_metrics` | app hosts | the monitoring host | monitoring host |
| 8409/tcp | `valkey_router_metrics` | app hosts | the monitoring host | monitoring host |
| 9100/tcp | `node_exporter` | ingest hosts | the monitoring host | monitoring host |
| 9598/tcp | `vector_metrics` | ingest hosts | the monitoring host | monitoring host |
| 8405/tcp | `clickhouse_proxy_metrics` | ingest hosts | the monitoring host | monitoring host |
| 8407/tcp | `app_api_proxy_metrics` | ingest hosts | the monitoring host | monitoring host |
| 9100/tcp | `node_exporter` | ClickHouse hosts | the monitoring host | monitoring host |
| 9100/tcp | `node_exporter` | Keeper hosts (= PostgreSQL hosts) | the monitoring host | monitoring host |
| 9364/tcp | `keeper_metrics` | Keeper hosts (= PostgreSQL hosts) | the monitoring host | monitoring host |
| 9100/tcp | `node_exporter` | PostgreSQL hosts | the monitoring host | monitoring host |
| 9100/tcp | `node_exporter` | the monitoring host | the monitoring host | monitoring host |
| 8008/tcp | `patroni_api` | PostgreSQL hosts | app hosts, PostgreSQL hosts, the monitoring host | full HA (3 postgres hosts) |
| 2379/tcp | `etcd_client` | PostgreSQL hosts | PostgreSQL hosts, the monitoring host | full HA (3 postgres hosts) |
| 2380/tcp | `etcd_peer` | PostgreSQL hosts | PostgreSQL hosts | full HA (3 postgres hosts) |
| 6379/tcp | `valkey` | PostgreSQL hosts | app hosts, PostgreSQL hosts, the monitoring host | full HA (2+ app hosts) |
| 26379/tcp | `sentinel` | PostgreSQL hosts | app hosts, PostgreSQL hosts, the monitoring host | full HA (2+ app hosts) |
| 22/tcp | `ssh` | all | management CIDR, app hosts | always (the first app host runs scripts/nano upgrade over SSH) |
<!-- END plan.py --port-matrix -->

The `full HA` rows apply to the nano 2.0.7+ full-HA inventory (three PostgreSQL hosts;
Valkey and Sentinel with two or more app hosts). A `pre-2.0.7` inventory needs only
the `always` rows: `python3 scripts/plan.py --firewall-tsv --inventory-schema pre-2.0.7`.

```bash
MGMT_CIDR=<operator management CIDR, or 35.235.240.0/20 for IAP>
python3 scripts/plan.py --firewall-tsv | tail -n +2 | while IFS=$'\t' read -r port target source key when; do
  case "$source" in
    mgmt) src="--source-ranges $MGMT_CIDR" ;;
    lb-app|lb-ingest) src="--source-ranges 130.211.0.0/22,35.191.0.0/16" ;;
    *) src="--source-tags nano-$source" ;;
  esac
  # GCP rule names allow only lowercase letters, digits and hyphens
  gcloud compute firewall-rules create "$NAME-$port-$source-$target" --network $NAME-vpc \
    --direction INGRESS --action ALLOW --rules tcp:$port $src --target-tags nano-$target
done
```

A custom-mode VPC denies other ingress by default; do not add broad
`10.40.0.0/16` allow rules.

## Object storage: cold tier and backups (Cloud Storage)

Two buckets in the deployment region, uniform bucket-level access, public
access prevention enforced:

```bash
for b in cold backup; do
  gcloud storage buckets create gs://$NAME-$b --location $REGION --uniform-bucket-level-access \
    --public-access-prevention --default-storage-class STANDARD
done
```

nano speaks the S3 API, which Cloud Storage serves at
`https://storage.googleapis.com` with **HMAC keys**. Create one service
account per bucket, grant it `roles/storage.objectAdmin` on **that bucket
only**, and have the operator create its HMAC key and enter it in nano
(Settings → Storage & Retention for the cold tier; the backup configuration
for backups):

```bash
gcloud iam service-accounts create $NAME-cold --display-name "nano cold tier"
gcloud storage buckets add-iam-policy-binding gs://$NAME-cold \
  --member serviceAccount:$NAME-cold@$PROJECT.iam.gserviceaccount.com --role roles/storage.objectAdmin
# operator, not the agent: gcloud storage hmac create $NAME-cold@$PROJECT.iam.gserviceaccount.com
```

The HMAC secret is shown once; it goes straight into nano, never into chat.
RustFS is the self-hosted S3-compatible alternative. Tiering moves are
free-space driven today (TTL-driven moves are planned).

## Identity for the VMs and the operator

- VMs need no Google Cloud permissions to run nano: create them with
  `--no-service-account --no-scopes`. Never use the default compute service
  account (it has broad project roles).
- Enable OS Login (`--metadata enable-oslogin=TRUE`) so SSH access follows IAM.
- The person or agent provisioning needs Compute Admin (or Compute Instance
  Admin plus Network Admin and Security Admin), Storage Admin on the two
  buckets, and Service Account Admin for the two bucket accounts.

## VMs

```bash
python3 scripts/plan.py <plan flags> --nodes-tsv | tail -n +2 | \
while IFS=$'\t' read -r name kind zone addr type data_gib data_type iops mbps extra; do
  disk=""
  [ "$data_gib" != 0 ] && disk="--create-disk name=$name-data,size=${data_gib}GB,type=$data_type,auto-delete=no,device-name=data"
  echo gcloud compute instances create $name --zone $zone --machine-type $type \
    --subnet $NAME-private --private-network-ip $addr --no-address \
    --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
    --boot-disk-size 100GB --boot-disk-type pd-balanced $disk \
    --no-service-account --no-scopes --shielded-secure-boot \
    --metadata enable-oslogin=TRUE --tags nano-<group for $kind> --labels nano-deployment=$NAME
done
```

The commands print first; run each after approval. The data disk appears as
`/dev/disk/by-id/google-data`; format and mount that path. `auto-delete=no`
keeps the data disk if a VM is deleted by mistake.

**Time sync:** Google's Ubuntu images run chrony against
`metadata.google.internal`. Check with `chronyc sources`.

## Load balancers

Two global external **Application Load Balancers** (`EXTERNAL_MANAGED`),
Google-managed certificates, backends on port 80 through one unmanaged
instance group per zone and role:

```bash
for z in a b c; do
  gcloud compute instance-groups unmanaged create $NAME-app-$z --zone $REGION-$z
  gcloud compute instance-groups set-named-ports $NAME-app-$z --zone $REGION-$z --named-ports http:80
  # add the app VMs of that zone:
  # gcloud compute instance-groups unmanaged add-instances $NAME-app-$z --zone $REGION-$z --instances nano-app-N
done
gcloud compute health-checks create http $NAME-app-ready --port 80 --request-path /readyz \
  --check-interval 10s --timeout 5s --healthy-threshold 2 --unhealthy-threshold 2
gcloud compute backend-services create $NAME-app --global --load-balancing-scheme EXTERNAL_MANAGED \
  --protocol HTTP --port-name http --health-checks $NAME-app-ready
# gcloud compute backend-services add-backend $NAME-app --global --instance-group $NAME-app-a --instance-group-zone $REGION-a  (each zone)
gcloud compute url-maps create $NAME-app --default-service $NAME-app
gcloud compute ssl-certificates create $NAME-app --domains <app hostname> --global
gcloud compute target-https-proxies create $NAME-app --url-map $NAME-app --ssl-certificates $NAME-app
gcloud compute addresses create $NAME-app-ip --global
gcloud compute forwarding-rules create $NAME-app --global --load-balancing-scheme EXTERNAL_MANAGED \
  --address $NAME-app-ip --target-https-proxy $NAME-app --ports 443
# the ingest LB the same way, with health check path /healthz and the ingest hostname
```

- **App health check `/readyz`** (nano 2.0.7+; `/healthz` before it). **Ingest
  `/healthz`**.
- **`X-Forwarded-For`:** Google appends `<client>, <load balancer IP>`.
  `trusted_proxy_cidrs` must hold Google's ranges (the plan adds them) **and**
  each load balancer's own address: pass `--trusted-proxy-cidr <app LB IP>/32
  --trusted-proxy-cidr <ingest LB IP>/32` to `plan.py` when you generate the
  inventory.
- **HEC indexer acknowledgements:** set session affinity on the ingest
  backend service (client IP, or a header-field affinity on
  the HEC request-channel header where the load balancer supports it), or send
  HEC without indexer acks.
- The internal ingest endpoint (`load_balancer.ingest_endpoint`) needs TLS on
  443 with a certificate chaining to the private cluster CA: use an internal
  Application Load Balancer with a self-managed certificate, and pass
  `--ingest-lb-address` and `--ingest-lb-tls-name` to `plan.py`.

DNS: A records for both hostnames to the two reserved addresses. Managed
certificates become active only after DNS points at them.

## Terraform starting point (optional)

A sketch, not a supported module. Review every value against the plan.

```hcl
# Starting point only: one ClickHouse replica as planned
resource "google_compute_disk" "ch_s1r1_data" {
  name = "nano-ch-s1r1-data"
  zone = "us-central1-a"            # plan: nodes[].zone
  type = "pd-ssd"
  size = 1500                       # plan: nodes[].disks[] (GiB)
  labels = { nano-deployment = var.name }
}
resource "google_compute_instance" "ch_s1r1" {
  name         = "nano-ch-s1r1"
  zone         = "us-central1-a"
  machine_type = "n2-highmem-8"     # plan: nodes[].instance
  tags         = ["nano-clickhouse", "nano-ingest"]
  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = 100
      type  = "pd-balanced"
    }
  }
  attached_disk {
    source      = google_compute_disk.ch_s1r1_data.id
    device_name = "data"
  }
  network_interface {
    subnetwork = google_compute_subnetwork.private.id
    network_ip = "10.40.1.12"       # plan: nodes[].address
  }
  metadata = { enable-oslogin = "TRUE" }
  shielded_instance_config { enable_secure_boot = true }
  labels = { nano-deployment = var.name }
}
```

## Managed PostgreSQL (Cloud SQL)

The production database for the Helm chart on GKE (`postgresql.mode:
external`). The migrator checks the version and extensions before it applies
anything; run `scripts/pg-preflight.py` first so a gap shows before `helm install`.

| Item | Requirement |
|---|---|
| Version | PostgreSQL 16 or newer (16, 17, 18 tested). Cloud SQL may default to 16, depending on when and how the instance was created (check with `gcloud sql instances describe $NAME-pg --format='value(databaseVersion)'`). 16 works from nano 2.0.11; 2.0.10 and earlier fail in the migrator with `unrecognized configuration parameter "transaction_timeout"`, so use `POSTGRES_17` there |
| Extensions | `pg_trgm`, `pgcrypto`, `uuid-ossp`. All supported, no database flags needed. Users created through Cloud SQL (`gcloud sql users create`) are in `cloudsqlsuperuser` and can create them |
| Parameters | No flags required. Allow at least 200 connections (about 20 per nano pod): the default depends on the tier's memory, so use 8 GB or more or set the `max_connections` flag |
| Schema | The nano user needs `CREATE` on schema `public` in the `nanosiem` database (PostgreSQL 15+ no longer grants it to every role). A database made with `gcloud sql databases create` and a user made through Cloud SQL have it (the user is in `cloudsqlsuperuser`, which owns the database). `pg-preflight.py` checks it; on `FAIL schema`, run `GRANT ALL ON SCHEMA public TO nanosiem;` as the `postgres` user, connected to `nanosiem` |
| Network | Private IP only (`--no-assign-ip`) through private services access on the GKE cluster's VPC (VPC-native cluster); require SSL |
| HA | Regional availability (`--availability-type=REGIONAL`): a standby in another zone of the region, automatic failover. Zonal is a single point of failure |

```bash
# once per VPC: private services access
gcloud compute addresses create google-managed-services-$NAME --global \
  --purpose=VPC_PEERING --prefix-length=16 --network=$NAME-vpc
gcloud services vpc-peerings connect --service=servicenetworking.googleapis.com \
  --ranges=google-managed-services-$NAME --network=$NAME-vpc
gcloud services vpc-peerings list --network=$NAME-vpc   # must list servicenetworking; don't pipe the connect into tail
gcloud sql instances create $NAME-pg --database-version=POSTGRES_17 --edition=ENTERPRISE \
  --region=$REGION --tier=db-custom-2-8192 --availability-type=REGIONAL \
  --network=projects/$PROJECT/global/networks/$NAME-vpc --no-assign-ip \
  --ssl-mode=ENCRYPTED_ONLY --storage-type=SSD --storage-size=50 --storage-auto-increase \
  --backup-start-time=03:00 --enable-point-in-time-recovery
gcloud sql databases create nanosiem --instance=$NAME-pg
```

Labels and the database user go through the Cloud SQL Admin REST API, with
the access token in a header file and the password read from a file, so
neither is ever on a command line. (`gcloud sql users create` takes the
password only as `--password=...`, which shows in `ps` and the shell history;
it has no `--prompt-for-password`.) The operator writes the password to
`pg-password.txt` themselves (mode 0600):

```bash
( umask 077; printf 'Authorization: Bearer %s\n' "$(gcloud auth print-access-token)" > gcp-auth-header.txt
  python3 -c 'import json,sys; print(json.dumps({"name": "nanosiem", "password": open(sys.argv[1]).read().strip()}))' \
    pg-password.txt > pg-user.json )
API=https://sqladmin.googleapis.com/v1/projects/$PROJECT/instances/$NAME-pg
curl -fsS -X POST -H @gcp-auth-header.txt -H 'Content-Type: application/json' --data-binary @pg-user.json "$API/users"
curl -fsS -X PATCH -H @gcp-auth-header.txt -H 'Content-Type: application/json' \
  --data "{\"settings\": {\"userLabels\": {\"nano-deployment\": \"$NAME\"}}}" "$API"
rm -f pg-user.json gcp-auth-header.txt
gcloud sql users list --instance=$NAME-pg --format='table(name,type)'   # nanosiem, BUILT_IN
```

Create the user this way, not with `CREATE ROLE` in SQL: users created
through Cloud SQL (gcloud or the API) belong to `cloudsqlsuperuser` and can
create the extensions; roles created in SQL cannot, and the migrator then
stops on `pg_trgm`. Use a URL-safe password (it is interpolated into
`DATABASE_URL`). The host is the
instance's private IP (`gcloud sql instances describe $NAME-pg --format='value(ipAddresses[0].ipAddress)'`).
Then check with `scripts/pg-preflight.py` ([helm.md](helm.md#step-0-preflight-read-only)).

## GKE for the Helm chart

The sections above build VMs for the compose topologies. For the Helm chart
([helm.md](helm.md)) the operator brings a GKE cluster. When they have none,
propose this and create it only after they approve (it costs money from the
first minute). Every command uses their `gcloud` session. Product guide:
nano.rs/docs/getting-started/kubernetes#gke.

Use **GKE Standard**, not Autopilot. nano is untested on Autopilot and not
supported there: the chart needs the ingest node pool label and taint
(`nano.rs/pool=ingest`, from the `standard` preset up), local SSD node pools
for `large`/`xlarge`, and a fixed number of nodes per zone for the zonal
ClickHouse and Keeper disks. Say so if the operator asks for Autopilot.

**Quota first** (read-only; show the operator the numbers). A default
project often cannot hold the HA layout: 6 x `n2-standard-8` is 48 vCPUs
(`CPUS_ALL_REGIONS` is often 32), and `SSD_TOTAL_GB` (often 500) counts every
pd-balanced disk, node boot disks (100 GB each by default) included. Two
1500Gi ClickHouse volumes plus six boot disks need about 3,900 GB, and even
90 days hot (`clickhouse.storage.size: 500Gi`) with two replicas is 1,000 GB
before the boot disks: more than the default 500 GB. Request increases, or
plan 90 days hot plus the GCS cold tier. Node boot disks on `pd-standard`
(`--disk-type pd-standard` on the cluster) move 600 GB off the SSD quota. For a
lab or test only, `clickhouse.storage.size: 150Gi` fits the default quota (a
GKE test ran on it); it is not a production size.

```bash
# `describe` has no --filter: flatten, then filter the output.
gcloud compute project-info describe --flatten=quotas \
  --format='csv[no-heading](quotas.metric,quotas.limit,quotas.usage)' | grep -E '^CPUS_ALL_REGIONS,'
gcloud compute regions describe $REGION --flatten=quotas \
  --format='csv[no-heading](quotas.metric,quotas.limit,quotas.usage)' | grep -E '^(CPUS|N2_CPUS|SSD_TOTAL_GB),'
```

A small HA cluster: regional, three zones, **two nodes per zone** (6 nodes).
Persistent disks are zonal: with one node per zone, draining or losing a node
leaves that zone's ClickHouse replica and Keeper member Pending (data safe,
no redundancy) until a node returns to that zone. Size the machine type from
the plan (`size.py --topology helm`). Set `clickhouse.zoneAware: true` (the
two replicas of a shard in different zones, Keeper over three zones) with
`antiAffinity: hard`. Reuse the VPC, subnet and Cloud NAT from
[Network](#network-one-vpc-three-zones).

`clusters create` adds the cluster to the kubeconfig and **switches its
current-context**. Point `KUBECONFIG` at a working-directory file first, so
the operator's `~/.kube/config` (and its production contexts) stays as it was:

```bash
export KUBECONFIG=$PWD/nano-deploy-work/kubeconfig
# about 5-10 minutes
gcloud container clusters create $NAME --region $REGION \
  --node-locations $REGION-a,$REGION-b,$REGION-c --num-nodes 2 \
  --machine-type n2-standard-8 \
  --network $NAME-vpc --subnetwork $NAME-private --enable-ip-alias \
  --gateway-api=standard --enable-dataplane-v2 \
  --workload-pool=$PROJECT.svc.id.goog \
  --release-channel regular --labels nano-deployment=$NAME
```

- `--num-nodes` is per zone. `n2-standard-8` (8 vCPU / 32 GB) matches the
  docs' HA sizing; a test at about 12.5 GB/day ran the HA values on 6 x
  `n2-highmem-4` (4 vCPU / 32 GB) when quota was short. Both are x86-64 with
  AVX2.
- `--gateway-api=standard`: without it there is no
  `gke-l7-global-external-managed` GatewayClass and the Gateways never get an
  address. Existing cluster: `gcloud container clusters update $NAME
  --region $REGION --gateway-api=standard`. The class appears a few minutes
  **after** the cluster reports RUNNING (about 3 minutes in a test), so a
  Step 0 preflight straight after creation reads "no Gateway implementation".
  Wait for it first:
  `until kubectl get gatewayclass gke-l7-global-external-managed >/dev/null 2>&1; do sleep 10; done`
  (bound it, e.g. 10 minutes).
- `--enable-dataplane-v2`: GKE Standard does **not** enforce NetworkPolicy by
  default, so the chart's `nano-vector-ingress` policy (Vector's OTLP ports
  only from the ingest edge) is silently ignored. Chart 2.0.10 and earlier
  rely on it to keep unauthenticated raw OTLP out; from 2.0.11 Vector's OTLP
  listeners only accept traffic through the authenticated ingest edge, and
  the policy is defense in depth. Vector's Prometheus metrics (`:9598`, no
  credential, read-only counters) are open to every pod on 2.0.11; from 2.0.12
  the policy admits them only from the nano namespace (add a scraper elsewhere
  with `vector.metrics.networkPolicyFrom`). Dataplane V2 is
  creation-time only; on an existing cluster check
  `gcloud container clusters describe $NAME --region $REGION --format='value(networkConfig.datapathProvider,networkPolicy.enabled)'`
  (`ADVANCED_DATAPATH` or `True` = enforced); otherwise the network policy
  add-on (`--update-addons=NetworkPolicy=ENABLED`, then
  `--enable-network-policy`) recreates the nodes, so ask first.
- `--workload-pool`: Workload Identity for the GCS cold tier without keys.
- Private nodes (`--enable-private-nodes`) need Cloud NAT (the license API,
  the nano registry and Docker Hub images) and control-plane access: they
  turn on authorized networks, which can start empty so `kubectl` times out.
  Add `--enable-master-authorized-networks --master-authorized-networks
  <operator CIDR>`, or `--enable-dns-access` and
  `gcloud container clusters get-credentials $NAME --region $REGION --dns-endpoint`.

Then, in order (each is a hard stop for the chart):

1. **Default StorageClass.** GKE's default is `standard-rwo` (pd-balanced,
   zonal, `WaitForFirstConsumer`); nothing to create. Confirm with
   `kubectl get storageclass`. `large`/`xlarge` need a local-SSD node pool and
   a StorageClass for it in `clickhouse.storage.storageClass`.

2. **Network policy check.** After install, prove enforcement (any HTTP
   status, even 401/405, means it is NOT enforced; enforced = timeout and
   `000`):

   ```bash
   kubectl run np-test -n default --rm -it --image=curlimages/curl:8.12.1 --restart=Never -- \
     curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://nano-vector-internal.nano.svc.cluster.local:4318/v1/logs
   ```

3. **Certificates (Certificate Manager map).** `values-gke.yaml` uses
   `tls.mode: cloud-managed` with `tls.gke.certificateMap`. The operator
   needs a domain they control and adds the DNS records; you never need DNS
   credentials:

   ```bash
   gcloud certificate-manager dns-authorizations create $NAME-app --domain=<app host>
   gcloud certificate-manager dns-authorizations create $NAME-ingest --domain=<ingest host>
   for h in app ingest; do   # the CNAME record the operator adds for each
     gcloud certificate-manager dns-authorizations describe $NAME-$h --format='value(dnsResourceRecord)'
   done
   # operator adds each CNAME, then:
   gcloud certificate-manager certificates create $NAME-app --domains=<app host> --dns-authorizations=$NAME-app
   gcloud certificate-manager certificates create $NAME-ingest --domains=<ingest host> --dns-authorizations=$NAME-ingest
   gcloud certificate-manager maps create $NAME-map
   gcloud certificate-manager maps entries create $NAME-app --map=$NAME-map --certificates=$NAME-app --hostname=<app host>
   gcloud certificate-manager maps entries create $NAME-ingest --map=$NAME-map --certificates=$NAME-ingest --hostname=<ingest host>
   gcloud certificate-manager certificates describe $NAME-app --format='value(managed.state)'   # ACTIVE
   ```

   No public DNS (evaluation only): upload a private-CA certificate for both
   names (`make-private-ca.sh`, then `gcloud certificate-manager certificates
   create <name> --certificate-file ... --private-key-file ...`), add the two
   map entries for it, and test with `curl --resolve`.

4. **Static IPs.** Reserve a global address per Gateway so DNS survives a
   reinstall; the operator creates A records for them:

   ```bash
   gcloud compute addresses create $NAME-app-ip $NAME-ingest-ip --global --ip-version=IPV4
   gcloud compute addresses list --global --filter="name~^$NAME-"
   ```

   Values (`values-gke-site.yaml`, after `values-gke.yaml`):

   ```yaml
   tls:
     gke:
       certificateMap: <name>-map
   gateway:
     addresses:
       app: [{type: NamedAddress, value: <name>-app-ip}]
       ingest: [{type: NamedAddress, value: <name>-ingest-ip}]
   clickhouse:
     zoneAware: true
   ```

   The chart renders the HealthCheckPolicies and a GCPBackendPolicy (310 s
   app timeout). It has no source-range setting on GKE: both load balancers
   are public.

5. **PostgreSQL.** For production, Cloud SQL with private IP, regional HA and
   `--ssl-mode=ENCRYPTED_ONLY` (matches `sslmode: require`; a client-cert mode
   would refuse nano). See [Managed PostgreSQL (Cloud SQL)](#managed-postgresql-cloud-sql).
   The first `vpc-peerings connect` in a project can fail with an
   authentication error while the Service Networking agent is provisioned;
   retry it. A database created with `gcloud sql databases create` is owned by
   `cloudsqlsuperuser`; that is fine. Tell the operator what a failover looks
   like: about 10-14 s of stalled API, sign-in and OTLP requests (no errors,
   HEC unaffected, nothing lost), and an OTLP request that timed out at the
   client may or may not have been stored (a 2.0.11 GKE test found it was
   not), so a retrying sender at worst duplicates it.

6. **Registry credential.** The chart's `registryCredentialRefresh` CronJob
   keeps `nano-registry` fresh (see [helm.md](helm.md)). After the pull, run
   `helm registry logout us-central1-docker.pkg.dev`: `helm registry login`
   can leave the credential in the OS keychain.

Teardown (only on request, and show the list first): `helm uninstall nano -n
nano` (it removes the `ClickHouseCluster`/`KeeperCluster` itself), then
`kubectl delete namespace nano` (PVCs, secret, leftover hook Jobs; the disks
go with the PVCs); the load balancers go with the Gateways. Then
`gcloud container clusters delete $NAME --region $REGION`, the Cloud SQL
instance, the two global addresses, the map entries, map, certificates and DNS
authorizations. If `gcloud services vpc-peerings delete` refuses ("producer
services still using this connection"), use `gcloud compute networks peerings
delete servicenetworking-googleapis-com --network $NAME-vpc`.
