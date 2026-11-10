# Azure

Cloud specifics for [cloud-vm.md](cloud-vm.md). Ask before every mutating
step. The commands use the operator's own `az` session.

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
