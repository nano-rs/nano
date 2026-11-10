# Google Cloud

Cloud specifics for [cloud-vm.md](cloud-vm.md). Ask before every mutating
step. The commands use the operator's own `gcloud` session.

```bash
export PROJECT=<project id> REGION=us-central1 NAME=<cluster name>
gcloud config list                     # show account and project, ask before going on
gcloud config set project $PROJECT
```

Label every resource `--labels nano-deployment=$NAME`.

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
| 3000/tcp | `api_internal` | app hosts | ingest hosts | always |
| 80/tcp | `ingest` | ingest hosts | ingest load balancer, app hosts | always |
| 8687/tcp | `vector_tap` | ingest hosts | app hosts | always |
| 5432/tcp | `postgres` | PostgreSQL hosts | app hosts, ClickHouse hosts, PostgreSQL hosts | always |
| 8123/tcp | `clickhouse_http` | ClickHouse hosts | app hosts, ingest hosts, ClickHouse hosts | always |
| 9000/tcp | `clickhouse_native` | ClickHouse hosts | app hosts, ingest hosts, ClickHouse hosts | always |
| 9009/tcp | `clickhouse_interserver` | ClickHouse hosts | ClickHouse hosts | always |
| 9363/tcp | `clickhouse_metrics` | ClickHouse hosts | app hosts | always |
| 9181/tcp | `keeper_client` | Keeper hosts (= PostgreSQL hosts) | app hosts, ClickHouse hosts, Keeper hosts (= PostgreSQL hosts) | always |
| 9234/tcp | `keeper_raft` | Keeper hosts (= PostgreSQL hosts) | Keeper hosts (= PostgreSQL hosts) | always |
| 8008/tcp | `patroni_api` | PostgreSQL hosts | app hosts, PostgreSQL hosts | full HA (3 postgres hosts) |
| 2379/tcp | `etcd_client` | PostgreSQL hosts | PostgreSQL hosts | full HA (3 postgres hosts) |
| 2380/tcp | `etcd_peer` | PostgreSQL hosts | PostgreSQL hosts | full HA (3 postgres hosts) |
| 6379/tcp | `valkey` | PostgreSQL hosts | app hosts, PostgreSQL hosts | full HA (2+ app hosts) |
| 26379/tcp | `sentinel` | PostgreSQL hosts | app hosts, PostgreSQL hosts | full HA (2+ app hosts) |
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
