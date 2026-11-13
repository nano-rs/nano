# Azure

Cloud specifics for [cloud-vm.md](cloud-vm.md) (VMs) and, at the end, for an
AKS cluster for the Helm chart ([AKS](#aks-for-the-helm-chart)). Ask before
every mutating step. The commands use the operator's own `az` session.

```bash
export LOC=eastus RG=<cluster name>-rg NAME=<cluster name> TAGS="nano-deployment=<cluster name>"
az account show --query '{subscription:name, id:id, user:user.name}'   # show it, ask before going on
```

## Instance and disk choices

`plan.py --cloud azure` picks from these families (catalog
`scripts/cloud-catalog.json`, eastus pay-as-you-go Linux prices verified
2026-11-10 from the Azure Retail Prices API):

| Role | Family | Disk |
|---|---|---|
| ClickHouse | `Ebdsv5` (8 GiB per vCPU) | Premium SSD v2, IOPS and MB/s provisioned from the shard's TB/day |
| ClickHouse, large hot set | `Lsv3` (local NVMe, RAID 0) | ephemeral; replicas re-seed |
| App | `Fsv2` | 128 GiB Premium SSD (P10) OS disk |
| PostgreSQL + Keeper (+ etcd, Sentinel) | `Dsv5` | Premium SSD v2 |
| Ingest | `Fsv2` | Premium SSD (P10, 128 GiB) data disk for Docker and Vector buffers |

Premium SSD v2 needs **zonal** VMs in eastus and cannot be an OS disk. `Fsv2`
lists no Premium SSD v2 support, so its disks are Premium SSD (v1). Every VM
is created in a specific zone (`--zone 1|2|3`, the plan's `zone`).

## Network: one VNet, three zones

Azure subnets span zones; the plan still uses one subnet per zone so that
addresses tell you the zone:

| Subnet | CIDR | Purpose |
|---|---|---|
| `private-1/2/3` | `10.40.1.0/24`, `10.40.2.0/24`, `10.40.3.0/24` | nano VMs in zones 1/2/3, no public IPs |
| `agw` | `10.40.8.0/24` (inside `10.40.8.0/22`) | Application Gateway v2 (dedicated subnet) |

```bash
az group create -n $RG -l $LOC --tags $TAGS
az network vnet create -g $RG -n $NAME-vnet --address-prefixes 10.40.0.0/16 --tags $TAGS
for z in 1 2 3; do
  az network vnet subnet create -g $RG --vnet-name $NAME-vnet -n private-$z --address-prefixes 10.40.$z.0/24
done
az network vnet subnet create -g $RG --vnet-name $NAME-vnet -n agw --address-prefixes 10.40.8.0/24
```

Egress: one zonal NAT gateway per zone, each attached to that zone's
`private-N` subnet (a subnet takes one NAT gateway, and a zonal gateway keeps
the other zones' egress through a zone loss). Hosts need the registry,
`api.nano.rs`, the platform feeds and the Ubuntu and Docker apt repositories.
Operator access: Azure Bastion or a jump host restricted to the management CIDR.

## Network security: one NSG, application security groups

Create an application security group (ASG) per firewall group: `app`,
`ingest`, `control`, `clickhouse`. Put each VM's NIC in the ASG of every role
it runs (co-located ingest VMs join `clickhouse` and `ingest`). One NSG on the
three private subnets carries the rules. The load-balancer source is the `agw`
subnet. The rules come from the renderer's port matrix:

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
for g in app ingest control clickhouse; do az network asg create -g $RG -n $NAME-$g --tags $TAGS; done
az network nsg create -g $RG -n $NAME-nsg --tags $TAGS
MGMT_CIDR=<operator management CIDR>; prio=200
python3 scripts/plan.py --firewall-tsv | tail -n +2 | while IFS=$'\t' read -r port target source key when; do
  case "$source" in
    mgmt) src="--source-address-prefixes $MGMT_CIDR" ;;
    lb-app|lb-ingest) src="--source-address-prefixes 10.40.8.0/24" ;;
    *) src="--source-asgs $NAME-$source" ;;
  esac
  prio=$((prio+1))
  az network nsg rule create -g $RG --nsg-name $NAME-nsg -n "$key-$source-$target" --priority $prio \
    --direction Inbound --access Allow --protocol Tcp $src --destination-asgs $NAME-$target \
    --destination-port-ranges $port
done
az network nsg rule create -g $RG --nsg-name $NAME-nsg -n deny-vnet-rest --priority 4000 \
  --direction Inbound --access Deny --protocol '*' --source-address-prefixes VirtualNetwork \
  --destination-address-prefixes '*' --destination-port-ranges '*'
for z in 1 2 3; do az network vnet subnet update -g $RG --vnet-name $NAME-vnet -n private-$z --network-security-group $NAME-nsg; done
```

Azure's default NSG rules allow all traffic inside the VNet; the
`deny-vnet-rest` rule above closes that, so only the listed flows remain. The
`AzureLoadBalancer` default rule (priority 65001) stays for platform probes.
Do not put this NSG on the `agw` subnet.

## Object storage: cold tier and backups

nano's tiering and backup clients speak the **S3 API**. Azure Blob Storage has
no S3 API, so on Azure:

- **Cold tier:** run RustFS (S3-compatible, self-hosted) on Azure VMs with
  managed disks, or use an external S3-compatible store; or keep all retention
  on local disk (`plan.py --hot-days <retention>`, more disk, no tier). The
  plan's cold-tier line is priced at Blob Hot LRS as a placeholder and listed
  as unverified.
- **Backups:** an Azure Files share mounted on the backup hosts (NFS 4.1 on a
  premium file share behind a private endpoint), used as a directory
  destination (`NANO_BACKUP_DESTINATION=path`), or the same S3-compatible store.
  Backups hold metadata by default, not event data.

Give the store its own least-privilege access key per purpose; the operator
enters it in nano.

## Identity and access

- VMs need no Azure permissions to run nano: no managed identity on them.
- The Application Gateway's TLS certificates live in Key Vault. Give the
  gateway a user-assigned identity with **Key Vault Secrets User** on that
  vault only, and reference the certificate by its secret ID. Never pass a
  certificate password on a command line.
- The person or agent provisioning needs **Contributor** on the resource group
  only (or Network Contributor plus Virtual Machine Contributor), and Key Vault
  certificate import rights for the operator.

## VMs

Image `Canonical:ubuntu-24_04-lts:server:latest`. Read the plan rows and show
each command before running it:

```bash
python3 scripts/plan.py <plan flags> --nodes-tsv | tail -n +2 | \
while IFS=$'\t' read -r name kind zone addr type data_gib data_type iops mbps extra; do
  z=$zone; subnet=private-$z
  echo az vm create -g $RG -n $name --zone $z --size $type --image Canonical:ubuntu-24_04-lts:server:latest \
    --vnet-name $NAME-vnet --subnet $subnet --private-ip-address $addr --public-ip-address "" \
    --nsg "" --admin-username <ssh user> --ssh-key-values <operator public key path> \
    --os-disk-size-gb 128 --storage-sku Premium_LRS --tags $TAGS
  if [ "$data_type" = premium-ssd-v2 ]; then
    echo az disk create -g $RG -n $name-data --zone $z --sku PremiumV2_LRS --size-gb $data_gib \
      ${iops:+--disk-iops-read-write $iops} ${mbps:+--disk-mbps-read-write $mbps} --tags $TAGS
    echo az vm disk attach -g $RG --vm-name $name --name $name-data --caching None
  elif [ "$data_type" = premium-ssd ]; then
    echo az vm disk attach -g $RG --vm-name $name --name $name-data --new --size-gb $data_gib --sku Premium_LRS
  fi
done
# then add each NIC to its ASG(s):
# az network nic ip-config update -g $RG --nic-name ${name}VMNic -n ipconfig$name --asgs $NAME-<group> [...]
```

The commands print first; run them one by one after approval. Data disks
appear as `/dev/sdc` and up (`lsblk` and `ls -l /dev/disk/azure/scsi1/`);
`Lsv3` NVMe devices are `/dev/nvme*n1`. The temporary disk (`/mnt`) is never
used for data.

**Time sync:** Azure VMs sync through the Hyper-V PTP clock. Current Ubuntu
images point chrony at `/dev/ptp_hyperv`; check with `chronyc sources`
(expect a `PHC0` refclock). Microsoft's guidance is to use `/dev/ptp_hyperv`,
never `/dev/ptp0`.

## Load balancers

One zone-redundant **Application Gateway v2** (`Standard_v2`, zones 1 2 3) in
the `agw` subnet with two HTTPS listeners (app and ingest hostnames), two
backend pools (app VMs; ingest VMs), HTTP to port 80, and health probes:

- app pool: custom probe `GET /readyz` (nano 2.0.7+; `/healthz` before it),
  host = the app hostname, interval 10 s, unhealthy threshold 2;
- ingest pool: custom probe `GET /healthz`, host = the ingest hostname.

```bash
az network public-ip create -g $RG -n $NAME-agw-ip --sku Standard --zone 1 2 3 --tags $TAGS
az network application-gateway create -g $RG -n $NAME-agw --sku Standard_v2 --capacity 2 --zones 1 2 3 \
  --vnet-name $NAME-vnet --subnet agw --public-ip-address $NAME-agw-ip --priority 100 \
  --http-settings-port 80 --http-settings-protocol Http --frontend-port 443 \
  --servers <nano-app-1 address> <nano-app-2 address> --identity <user-assigned identity id> \
  --key-vault-secret-id <app certificate secret id> --tags $TAGS
az network application-gateway probe create -g $RG --gateway-name $NAME-agw -n app-ready \
  --protocol Http --host <app hostname> --path /readyz --interval 10 --threshold 2 --timeout 5
# add the ingest listener, pool, probe (/healthz) and rule the same way
```

**`X-Forwarded-For`:** Application Gateway appends the client as `IP:port`.
Add a rewrite rule set on both routing rules that **sets** `X-Forwarded-For`
to `{var_client_ip}`, so the edges see one clean address from a trusted
source. The plan's `trusted_proxy_cidrs` (`10.40.8.0/22`) contains the `agw`
subnet.

**HEC indexer acknowledgements** reach the right ingest host only with
cookie-based affinity and a sender that keeps cookies. Otherwise send HEC
without indexer acks.

The internal ingest endpoint (`load_balancer.ingest_endpoint`) needs TLS on
443 with a certificate that chains to the private cluster CA: a second,
private-frontend listener on the gateway, or an internal gateway. A Standard
Load Balancer cannot terminate TLS. Pass `--ingest-lb-address` and
`--ingest-lb-tls-name` to `plan.py`.

DNS: A records for both hostnames to the gateway's public IP.

## Terraform starting point (optional)

A sketch, not a supported module. Review every value against the plan.

```hcl
# Starting point only: one ClickHouse replica with its Premium SSD v2 data disk
resource "azurerm_linux_virtual_machine" "ch_s1r1" {
  name                  = "nano-ch-s1r1"
  resource_group_name   = azurerm_resource_group.nano.name
  location              = var.location
  zone                  = "1"                          # plan: nodes[].zone
  size                  = "Standard_E8bds_v5"          # plan: nodes[].instance
  admin_username        = var.ssh_user
  network_interface_ids = [azurerm_network_interface.ch_s1r1.id]
  admin_ssh_key {
    username   = var.ssh_user
    public_key = file(var.ssh_public_key_path)
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = 128
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
  tags = { "nano-deployment" = var.name }
}
resource "azurerm_managed_disk" "ch_s1r1_data" {
  name                 = "nano-ch-s1r1-data"
  resource_group_name  = azurerm_resource_group.nano.name
  location             = var.location
  zone                 = "1"
  storage_account_type = "PremiumV2_LRS"
  create_option        = "Empty"
  disk_size_gb         = 1500                          # plan: nodes[].disks[]
  disk_iops_read_write = 4000
  disk_mbps_read_write = 150
}
```

## Managed PostgreSQL (Azure flexible server)

The production database for the Helm chart on AKS (`postgresql.mode:
external`). The migrator checks the version and extensions before it applies
anything; run `scripts/pg-preflight.py` first so a gap shows before `helm install`.

| Item | Requirement |
|---|---|
| Version | PostgreSQL 16 or newer (16, 17 and 18 tested). 2.0.10 and earlier need 17+ |
| Extensions | `pg_trgm`, `pgcrypto`, `uuid-ossp`, **allow-listed in the `azure.extensions` server parameter**. Without it the migrator stops with `extension "pg_trgm" is not allow-listed`. Nothing else is needed (no `shared_preload_libraries`); `btree_gin`, `btree_gist` and `citext` are not used |
| Parameters | `azure.extensions` as above. Default `require_secure_transport=ON` is fine (`sslmode: require`). Allow at least 200 connections (about 20 per nano pod): avoid Burstable B1ms/B1s (50 connections, no HA) |
| Schema | The nano user needs `CREATE` on schema `public` in its database. On flexible server `public` belongs to `azure_pg_admin` in new databases, so the database owner can't create tables there and the first migration fails with `permission denied for schema public`. The bootstrap SQL below fixes it (`ALTER SCHEMA public OWNER TO nanosiem`) |
| Network | Private access (VNet integration): a subnet delegated to `Microsoft.DBforPostgreSQL/flexibleServers` in, or peered with, the AKS VNet, and a private DNS zone linked to the AKS VNet. Or a private endpoint. No public access |
| HA | Zone-redundant HA (standby in another zone): `--zonal-resiliency Enabled --zone 1 --standby-zone 2` on az 2.88 and newer (older az: `--high-availability ZoneRedundant`). Not every region, and not the Burstable tier, offers it; then use same-zone HA (`--zonal-resiliency Enabled --allow-same-zone`; older az: `--high-availability SameZone`), which protects against a server failure only, and say so to the operator |

The operator creates the server (portal, Terraform with the admin password
from Key Vault, or `az postgres flexible-server create` with `--version 17
--tier GeneralPurpose --sku-name <SKU> --zonal-resiliency Enabled --zone 1
--standby-zone 2 --vnet ... --subnet ... --private-dns-zone ... --tags $TAGS`).
Never pass `--admin-password` on a command line. Check `az --version` first:
az 2.88 removed `--high-availability` (`unrecognized arguments`).

Pick the SKU from what the region offers, not from an example:

```bash
az postgres flexible-server list-skus -l $PG_LOC -o table   # GeneralPurpose, 2+ vCores, HA column
```

A listed SKU can still be refused at create time (`SkuNotAvailable`: in one
test `Standard_D2ds_v5` was refused in eastus2 while `Standard_D2ads_v5`
worked). Each failed create costs about 5 minutes; on a refusal try the
other family of the same size (`ds` / `ads`) before another region.
Then allow the extensions, keeping any value already there:

```bash
az postgres flexible-server parameter show -g $RG --server-name $NAME-pg \
  --name azure.extensions --query value -o tsv
az postgres flexible-server parameter set -g $RG --server-name $NAME-pg \
  --name azure.extensions --value <existing>,pg_trgm,pgcrypto,uuid-ossp   # drop '<existing>,' if it was empty
```

The change applies without a restart. If zone-redundant HA is refused
("not supported in this region" or for the SKU), create it with `SameZone`.

Create the role and database as the admin user, in `psql` (`\password`
prompts, so the password never lands in history or on a command line), then
give the nano user schema `public` in its database:

```sql
CREATE ROLE nanosiem LOGIN;
\password nanosiem
GRANT nanosiem TO <admin user>;          -- PostgreSQL 16+: needed before ... OWNER nanosiem
CREATE DATABASE nanosiem OWNER nanosiem;
\connect nanosiem
ALTER SCHEMA public OWNER TO nanosiem;   -- flexible server: public belongs to azure_pg_admin
```

Without the last statement the first migration fails with `permission denied
for schema public` (`GRANT ALL ON SCHEMA public TO nanosiem;` works too). The
owner can create the three trusted extensions itself. Use a URL-safe
password (it is interpolated into `DATABASE_URL`), then check with
`scripts/pg-preflight.py` ([helm.md](helm.md#step-0-preflight-read-only)); from
2.0.12 it fails (`FAIL schema`) with this fix when the step was missed.

**Private-only server: run `psql` in a one-off pod.** The server has no
public address, so `psql` from a workstation can't reach it. Run the SQL above
from a temporary pod in the AKS cluster, with both passwords in a temporary
Secret and never on a command line: the "Reaching a private RDS or Azure
server" block in the product guide
(nano.rs/docs/getting-started/kubernetes#managed-postgresql-requirements),
with `user=<admin user> host=<server>.postgres.database.azure.com`. Delete
the Secret afterwards. (Alternative: `az postgres flexible-server execute`
needs a temporary public firewall rule; don't open one on a private server.)

**PostgreSQL in another region.** Some subscriptions are refused flexible
server in the cluster's region (`Provisioning is restricted in this region`).
Prefer asking for access in that region. If the operator accepts another
region, the private layout is:

1. a VNet in the PostgreSQL region with a subnet delegated to
   `Microsoft.DBforPostgreSQL/flexibleServers` (non-overlapping with the AKS
   VNet, e.g. `10.60.0.0/16`);
2. **global VNet peering in both directions** between that VNet and the AKS
   VNet (`az network vnet peering create ... --allow-vnet-access` twice);
3. **one** private DNS zone (`<name>.private.postgres.database.azure.com`)
   linked to **both** VNets (`az network private-dns link vnet create` twice),
   passed to the server create with `--private-dns-zone`.

Cross-region traffic is billed and adds latency to every query; with 2.0.11
the first migration took about 6 minutes cross-region (eastus to eastus2),
well inside `--timeout 30m`.

## AKS for the Helm chart

The sections above build VMs for the compose topologies. For the Helm chart
([helm.md](helm.md)) the operator brings an AKS cluster. When they have none,
propose this and create it only after they approve (it costs money from the
first minute). Every command uses their `az` session. Product guide:
nano.rs/docs/getting-started/kubernetes#azure-aks-with-application-gateway-for-containers.
Microsoft's Application Gateway for Containers (AGC) quickstarts are the
reference for the Azure steps; this lists what nano needs from them.

**Quota first** (read-only; show the operator the numbers). New subscriptions
often have 10 regional vCPUs and 0 for a VM family. Six 8-vCPU nodes need 48
in both the regional total and the family:

```bash
az vm list-usage -l $LOC -o table | grep -Ei 'Total Regional vCPUs|DDSv6|DDSv5'
```

Raising them (`az quota update`, or the portal) is the operator's call; in
one test Ddsv6 was granted in minutes while a DDSv5 request was refused, so
offer the other family when one is refused. Also check that managed
PostgreSQL is offered in the region (some subscriptions are refused in
eastus) before you pick `$LOC`.

Register the providers AGC needs (once per subscription):

```bash
for p in Microsoft.ContainerService Microsoft.Network Microsoft.NetworkFunction Microsoft.ServiceNetworking; do
  az provider register --namespace $p
done
az extension add --name alb
```

A small HA cluster: three zones, **two nodes per zone** (6 nodes), Azure CNI
overlay with the Cilium dataplane, OIDC issuer and workload identity, in a
VNet with a subnet for the nodes and a /24 delegated to AGC. Azure Disk LRS
volumes are zonal: with one node per zone, draining or losing a node leaves
that zone's ClickHouse replica and Keeper member Pending (data safe, no
redundancy) until a node returns to that zone. Size the VM from the plan
(`size.py --topology helm`). Set `clickhouse.zoneAware: true` with
`antiAffinity: hard`.

```bash
az network vnet create -g $RG -n $NAME-aks-vnet --address-prefixes 10.50.0.0/16 --tags $TAGS
az network vnet subnet create -g $RG --vnet-name $NAME-aks-vnet -n aks --address-prefixes 10.50.0.0/20
az network vnet subnet create -g $RG --vnet-name $NAME-aks-vnet -n agc --address-prefixes 10.50.16.0/24 \
  --delegations Microsoft.ServiceNetworking/trafficControllers
# about 5 minutes
az aks create -g $RG -n $NAME -l $LOC --tags $TAGS --nodepool-tags $TAGS \
  --tier standard --zones 1 2 3 --node-count 6 --node-vm-size Standard_D8ds_v6 \
  --network-plugin azure --network-plugin-mode overlay --network-dataplane cilium \
  --vnet-subnet-id $(az network vnet subnet show -g $RG --vnet-name $NAME-aks-vnet -n aks --query id -o tsv) \
  --enable-oidc-issuer --enable-workload-identity --no-ssh-key
```

- One pool with `--zones 1 2 3 --node-count 6` spreads nodes best-effort; to
  guarantee two per zone, add one node pool per zone (`az aks nodepool add
  --zones <z> --node-count 2`). `Standard_D8ds_v6` and `_v5` are x86-64 with
  AVX2.
- `--network-dataplane cilium` makes Cilium **enforce NetworkPolicy**.
  Without it (or `--network-policy azure|calico`), AKS stores the chart's
  `nano-vector-ingress` policy and silently ignores it; chart 2.0.10 and
  earlier rely on it to keep unauthenticated raw OTLP out of Vector (from
  2.0.11 Vector's OTLP listeners only accept traffic through the
  authenticated ingest edge, and the policy is defense in depth). Existing
  cluster: `az aks show -g $RG -n $NAME --query networkProfile.networkPolicy`
  (`none` or empty = not enforced). After install, prove it (enforced =
  timeout and `000`; any HTTP status means it is not):

  ```bash
  kubectl run np-test -n default --rm -it --image=curlimages/curl:8.12.1 --restart=Never -- \
    curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://nano-vector-internal.nano.svc.cluster.local:4318/v1/logs
  ```

- With a VNet you bring, the cluster's identity needs Network Contributor on
  it. A user-assigned control-plane identity (`--assign-identity`) lets you
  grant that before the create.

Then, in order (each is a hard stop for the chart):

1. **Default StorageClass.** AKS ships `default` (Azure Disk CSI, LRS,
   zonal); nothing to create. Confirm with `kubectl get storageclass`.

2. **ALB controller (workload identity, no secrets).** As in Microsoft's
   quickstart: a managed identity with a federated credential for the
   controller's service account, **Reader** on the node resource group, then
   the controller's Helm chart:

   ```bash
   az identity create -g $RG -n azure-alb-identity --tags $TAGS
   ALB_ID=$(az identity show -g $RG -n azure-alb-identity --query principalId -o tsv)
   MC_RG=$(az aks show -g $RG -n $NAME --query nodeResourceGroup -o tsv)
   az role assignment create --assignee-object-id $ALB_ID --assignee-principal-type ServicePrincipal \
     --role Reader --scope $(az group show -n $MC_RG --query id -o tsv)
   az identity federated-credential create -g $RG --identity-name azure-alb-identity -n azure-alb-identity \
     --issuer $(az aks show -g $RG -n $NAME --query oidcIssuerProfile.issuerUrl -o tsv) \
     --subject system:serviceaccount:azure-alb-system:alb-controller-sa
   helm install alb-controller oci://mcr.microsoft.com/application-lb/charts/alb-controller \
     --namespace azure-alb-helm --create-namespace --version <current, e.g. 1.13.0> \
     --set albController.namespace=azure-alb-system \
     --set albController.podIdentity.clientID=$(az identity show -g $RG -n azure-alb-identity --query clientId -o tsv)
   ```

   Then give the identity **Network Contributor** on the `agc` subnet, and
   **AppGw for Containers Configuration Manager** on the resource group that
   holds the AGC.

3. **AGC: bring your own (recommended) or managed.** BYO was the tested path:
   the frontend host names are known before install, and the AGC outlives a
   reinstall.

   ```bash
   az network alb create -g $RG -n $NAME-agc --tags $TAGS
   az network alb frontend create -g $RG --alb-name $NAME-agc -n fe-app --tags $TAGS
   az network alb frontend create -g $RG --alb-name $NAME-agc -n fe-ingest --tags $TAGS
   # about 5-6 minutes
   az network alb association create -g $RG --alb-name $NAME-agc -n assoc-aks \
     --subnet $(az network vnet subnet show -g $RG --vnet-name $NAME-aks-vnet -n agc --query id -o tsv)
   az network alb frontend show -g $RG --alb-name $NAME-agc -n fe-app --query fqdn -o tsv
   ```

   Values (`values-aks.yaml`, after `values-azure.yaml`):

   ```yaml
   gateway:
     annotations:
       alb.networking.azure.io/alb-id: /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ServiceNetworking/trafficControllers/<name>-agc
     addresses:
       app: [{type: alb.networking.azure.io/alb-frontend, value: fe-app}]
       ingest: [{type: alb.networking.azure.io/alb-frontend, value: fe-ingest}]
   clickhouse:
     zoneAware: true
   ```

   Managed instead: create an `ApplicationLoadBalancer` resource naming the
   `agc` subnet in a namespace of your choice; the controller creates the AGC
   and a frontend per Gateway. Then set only
   `gateway.annotations: {alb.networking.azure.io/alb-namespace: <ns>,
   alb.networking.azure.io/alb-name: <name>}`, and read the frontend host
   names from `kubectl -n nano get gateway` after install.

   The operator CNAMEs the app and ingest host names to the two frontend
   FQDNs (`*.alb.azure.com`). AGC gets no backend timeout or health-check
   policy from the chart: the AGC default request timeout applies to long
   searches (untested), and readiness probes serve as health checks.

4. **Certificates.** `values-azure.yaml` uses `tls.mode: cert-manager`
   (`cloud-managed` is refused on Azure). Install cert-manager and a
   ClusterIssuer for both host names; set `tls.certManager.issuerRef.name`.
   Use the operator's own domain: Let's Encrypt on `*.alb.azure.com` names
   shares azure.com's rate limit. To bring certificates instead, set
   `tls.mode: existingSecret` in `values-aks.yaml` (layered after
   `values-azure.yaml`, so it wins; that is the one exception to "don't set
   `tls.mode`").

   **Evaluation without a domain:** use the AGC frontends' own host names
   (`az network alb frontend show ... --query fqdn`) as the app and ingest
   host names, with a private CA issued by cert-manager itself
   (on AKS cert-manager issues it in the cluster, so `make-private-ca.sh`,
   used for this on GKE and EKS, is not needed). Senders and browsers must trust
   `nano-private-ca`'s `ca.crt`:

   ```yaml
   apiVersion: cert-manager.io/v1
   kind: ClusterIssuer
   metadata: {name: selfsigned-bootstrap}
   spec: {selfSigned: {}}
   ---
   apiVersion: cert-manager.io/v1
   kind: Certificate
   metadata: {name: nano-private-ca, namespace: cert-manager}
   spec:
     isCA: true
     commonName: nano-private-ca
     secretName: nano-private-ca
     privateKey: {algorithm: ECDSA, size: 256}
     issuerRef: {name: selfsigned-bootstrap, kind: ClusterIssuer}
   ---
   apiVersion: cert-manager.io/v1
   kind: ClusterIssuer
   metadata: {name: nano-private-ca}
   spec: {ca: {secretName: nano-private-ca}}
   ```

   Then `tls.certManager.issuerRef.name: nano-private-ca`. Read the CA for
   clients with `kubectl -n cert-manager get secret nano-private-ca -o
   jsonpath='{.data.ca\.crt}' | base64 -d > nano-ca.crt`.

5. **PostgreSQL.** For production, flexible server with the three extensions
   allow-listed **before** install (otherwise the first migration burns its
   retries on `not allow-listed`). See
   [Managed PostgreSQL (Azure flexible server)](#managed-postgresql-azure-flexible-server).
   Keep it in the cluster's region when you can; a cross-region server
   slows the first migration enough to hit Deployment progress deadlines on
   chart 2.0.10 (for the cross-region layout see
   [PostgreSQL in another region](#managed-postgresql-azure-flexible-server)).
   Tell the operator what a failover looks like: a forced failover (same-zone
   or zone-redundant) gave about 30 s of failed sign-ins and API writes and no
   HEC loss. On 2.0.11, OTLP failed with HTTP 500 for about 48 s (senders drop
   500); from 2.0.12 it answers 503 with `Retry-After` until the API is back
   ([known-issues.md](known-issues.md)).

7. **Tag what AKS creates.** `--tags` on the commands above does not reach
   resources Azure creates for you: the PVC disks in the `MC_` group (the AGC
   frontends get tags only from their own `--tags`, as above). After install,
   tag the disks of the `nano` namespace and check nothing is left untagged:

   ```bash
   MC_RG=$(az aks show -g $RG -n $NAME --query nodeResourceGroup -o tsv)
   for id in $(az disk list -g $MC_RG --query "[?tags.\"kubernetes.io-created-for-pvc-namespace\"=='nano'].id" -o tsv); do
     az resource tag --is-incremental --ids "$id" --tags $TAGS -o none
   done
   az resource list -g $MC_RG --query "[?tags.\"nano-deployment\"==null].{name:name,type:type}" -o table
   az resource list -g $RG --query "[?tags.\"nano-deployment\"==null].{name:name,type:type}" -o table
   ```

   To tag disks as they are created, give the chart a StorageClass that
   copies `default` with the Azure Disk CSI parameter
   `tags: nano-deployment=<cluster name>`, and set it as `global.storageClass`
   and `clickhouse.storage.storageClass` (both `""` = the cluster default).

6. **Registry credential.** The chart's `registryCredentialRefresh` CronJob
   keeps `nano-registry` fresh (see [helm.md](helm.md)). After the pull, run
   `helm registry logout us-central1-docker.pkg.dev`.

Teardown (only on request, and show the list first): `helm uninstall nano -n
nano` (it removes the `ClickHouseCluster`/`KeeperCluster` itself), then
`kubectl delete namespace nano` (PVCs, secret, leftover hook Jobs). With
everything in one resource group, `az group delete -n $RG` also removes the
cluster's `MC_` node resource group, the AGC, identities and role assignments
at those scopes. It leaves subscription-level changes (quota increases,
registered providers) and the `NetworkWatcher_<region>` resources Azure
auto-creates in `NetworkWatcherRG`, which other workloads may share: tell the
operator, don't delete them.
