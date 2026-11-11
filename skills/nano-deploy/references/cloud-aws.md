# AWS

Cloud specifics for [cloud-vm.md](cloud-vm.md) (VMs) and, at the end, for an
EKS cluster for the Helm chart ([Amazon EKS](#amazon-eks-for-the-helm-chart)). Run every mutating command
only after the operator approves that step. The commands use the operator's
own `aws` CLI session; you never handle their keys.

Set once (from the plan and intake):

```bash
export AWS_REGION=us-east-1 NAME=<cluster name> TAG="Key=nano-deployment,Value=<cluster name>"
aws sts get-caller-identity          # show the account and principal, ask before going on
```

## Instance and disk choices

`plan.py --cloud aws` picks from these families (catalog `scripts/cloud-catalog.json`,
us-east-1 list prices verified 2026-11-10 from the AWS price-list API):

| Role | Family | Disk |
|---|---|---|
| ClickHouse | `r7i` (8 GiB per vCPU) | gp3, IOPS and throughput provisioned from the shard's TB/day |
| ClickHouse, large hot set | `i4i` (local NVMe, RAID 0) | instance store: ephemeral; replicas re-seed |
| App | `c7i` | 100 GiB gp3 root (Docker on root) |
| PostgreSQL + Keeper (+ etcd, Sentinel) | `m7i` | gp3 with provisioned IOPS |
| Ingest | `c7i` | gp3 data disk for Docker and the Vector disk buffers |

Graviton (`r7g`, `r7gd`) is not in the plan: preflight requires x86-64 with
AVX2 for the published images. Encrypt every EBS volume (`Encrypted=true`).

## Network: one VPC across 3 Availability Zones

From the plan's `network` block (default `10.40.0.0/16`):

| Subnet | CIDR | Purpose |
|---|---|---|
| private-a/b/c | `10.40.1.0/24`, `10.40.2.0/24`, `10.40.3.0/24` | every nano VM, no public IPs |
| lb-a/b/c | `10.40.8.0/24`, `10.40.9.0/24`, `10.40.10.0/24` (inside `10.40.8.0/22`) | the two ALBs and the NAT gateways |

```bash
VPC=$(aws ec2 create-vpc --cidr-block 10.40.0.0/16 --tag-specifications "ResourceType=vpc,Tags=[{$TAG}]" --query Vpc.VpcId --output text)
aws ec2 modify-vpc-attribute --vpc-id $VPC --enable-dns-hostnames
i=0; for az in ${AWS_REGION}a ${AWS_REGION}b ${AWS_REGION}c; do i=$((i+1))
  aws ec2 create-subnet --vpc-id $VPC --availability-zone $az --cidr-block 10.40.$i.0/24 \
    --tag-specifications "ResourceType=subnet,Tags=[{$TAG},{Key=Name,Value=$NAME-private-$az}]"
  aws ec2 create-subnet --vpc-id $VPC --availability-zone $az --cidr-block 10.40.$((i+7)).0/24 \
    --tag-specifications "ResourceType=subnet,Tags=[{$TAG},{Key=Name,Value=$NAME-lb-$az}]"
done
```

Then: an internet gateway and a public route table for the `lb-*` subnets; one
NAT gateway per zone in its `lb-*` subnet, and one private route table per
zone sending `0.0.0.0/0` to that zone's NAT (a zone loss must not cut the
others' egress); an S3 **gateway endpoint** on the private route tables so
tiering and backup traffic stays off the NAT. Egress the hosts need: the
registry, `api.nano.rs` (license), the platform feeds, Ubuntu and Docker apt
repositories. Air-gapped installs follow [operate.md](operate.md#offline-license).

Access for the operator: AWS Systems Manager Session Manager or a bastion in
an `lb-*` subnet restricted to the management CIDR. Never give nano VMs public IPs.

## Security groups

One security group per firewall group: `app`, `ingest`, `control`
(PostgreSQL + Keeper), `clickhouse`, `lb-app`, `lb-ingest`. A VM gets the
group of every role it runs (ClickHouse VMs with co-located ingest get both
`clickhouse` and `ingest`). The rules come from the renderer's port matrix:

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

Create the groups, then apply every rule from the plan (each rule references
the source group, never a CIDR, except `mgmt`):

```bash
# bash 3.2 compatible (macOS): one variable per group, SG_app, SG_lb_app, ...
sg() { v="SG_$(printf %s "$1" | tr - _)"; printf %s "${!v}"; }
for g in app ingest control clickhouse lb-app lb-ingest; do
  id=$(aws ec2 create-security-group --vpc-id $VPC --group-name $NAME-$g \
    --description "nano $g" --tag-specifications "ResourceType=security-group,Tags=[{$TAG}]" \
    --query GroupId --output text)
  eval "SG_$(printf %s "$g" | tr - _)=$id"
done
MGMT_CIDR=<operator management CIDR>
python3 scripts/plan.py --firewall-tsv | tail -n +2 | while IFS=$'\t' read -r port target source key when; do
  if [ "$source" = mgmt ]; then peer="IpRanges=[{CidrIp=$MGMT_CIDR}]"; else peer="UserIdGroupPairs=[{GroupId=$(sg "$source")}]"; fi
  aws ec2 authorize-security-group-ingress --group-id "$(sg "$target")" \
    --ip-permissions "IpProtocol=tcp,FromPort=$port,ToPort=$port,$peer"
done
# The ALBs accept HTTPS from senders and users (narrow these to known CIDRs when possible)
aws ec2 authorize-security-group-ingress --group-id "$(sg lb-app)" --protocol tcp --port 443 --cidr <user CIDR>
aws ec2 authorize-security-group-ingress --group-id "$(sg lb-ingest)" --protocol tcp --port 443 --cidr <sender CIDR>
```

The installer never changes host firewalls. With security groups doing the
filtering, Docker's published ports are reachable only from the allowed
groups.

## Object storage: cold tier and backups (S3)

Two buckets, both in the deployment region, Block Public Access on, default
encryption on, versioning on:

- `<name>-cold`: ClickHouse cold tier. Configure it after install in
  **Settings → Storage & Retention** (endpoint `https://s3.<region>.amazonaws.com`).
  Today moves are free-space driven; TTL-driven moves are planned.
- `<name>-backup`: `scripts/nano backup` / the automatic backup service
  (`NANO_BACKUP_DESTINATION=s3`). Backups hold metadata by default, not event
  data. Add a lifecycle rule for old noncurrent versions.

nano's S3 clients take an access key, not an instance role. Create **one IAM
user per bucket** with only this policy (replace `<bucket>`), and have the
operator create the access key and enter it in nano themselves:

```json
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"], "Resource": "arn:aws:s3:::<bucket>"},
  {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"],
   "Resource": "arn:aws:s3:::<bucket>/*"}]}
```

Add a bucket policy that denies requests not coming through the VPC endpoint
(`aws:SourceVpce`). RustFS is the self-hosted S3-compatible option if the
operator does not want S3.

## IAM for the VMs and the operator

- VMs need no AWS permissions to run nano. Attach no instance profile, or
  only `AmazonSSMManagedInstanceCore` when Session Manager is the access path.
  Require IMDSv2 (`--metadata-options HttpTokens=required`).
- The person or agent provisioning needs EC2 (VPC, subnets, SGs, instances,
  volumes), Elastic Load Balancing, ACM (read and request), S3 (create
  buckets), and IAM (create the two bucket users). Nothing else.

## VMs

Ubuntu 24.04 LTS from Canonical's public SSM parameter (owner 099720109477):

```bash
AMI=resolve:ssm:/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id
python3 scripts/plan.py <plan flags> --nodes-tsv | tail -n +2 | \
while IFS=$'\t' read -r name kind zone addr type data_gib data_type iops mbps extra; do
  subnet=$(aws ec2 describe-subnets --filters Name=vpc-id,Values=$VPC Name=availability-zone,Values=$zone \
    Name=cidr-block,Values="${addr%.*}.0/24" --query 'Subnets[0].SubnetId' --output text)
  bdm='[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":100,"VolumeType":"gp3","Encrypted":true}}'
  if [ "$data_type" = gp3 ]; then
    bdm="$bdm"',{"DeviceName":"/dev/sdf","Ebs":{"VolumeSize":'$data_gib',"VolumeType":"gp3","Encrypted":true,"DeleteOnTermination":false'
    [ "$iops" != 0 ] && bdm="$bdm"',"Iops":'$iops',"Throughput":'$mbps
    bdm="$bdm"'}}'
  fi
  bdm="$bdm]"
  echo "$name $type $zone $addr: $bdm"      # show, then run after approval:
  # aws ec2 run-instances --image-id $AMI --instance-type $type --subnet-id $subnet \
  #   --private-ip-address $addr --security-group-ids <groups for $kind> --key-name <operator key> \
  #   --block-device-mappings "$bdm" --metadata-options HttpTokens=required,HttpEndpoint=enabled \
  #   --tag-specifications "ResourceType=instance,Tags=[{$TAG},{Key=Name,Value=$name}]" \
  #   "ResourceType=volume,Tags=[{$TAG},{Key=Name,Value=$name}]"
done
```

`DeleteOnTermination=false` keeps a data volume if an instance is terminated
by mistake. On Nitro instances EBS volumes appear as `/dev/nvme1n1`, and so
on; match them by size with `lsblk` before formatting. `i4i` local NVMe
devices show as `Amazon EC2 NVMe Instance Storage` in `nvme list`.

**Time sync:** Ubuntu's chrony on EC2 uses the Amazon Time Sync Service
(`169.254.169.123`). Check with `chronyc sources`; if it is missing, add
`server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4` to
`/etc/chrony/chrony.conf`.

## Load balancers

Two internet-facing **Application Load Balancers** across the three `lb-*`
subnets, TLS certificates from ACM, forwarding HTTP to port 80 on the hosts.
An ALB appends the client address to `X-Forwarded-For`, and nano's edges take
the right-most address that is not in `trusted_proxy_cidrs` (the plan sets
`10.40.8.0/22`, the LB subnets).

```bash
TG_APP=$(aws elbv2 create-target-group --name $NAME-app --protocol HTTP --port 80 --vpc-id $VPC \
  --target-type instance --health-check-path /readyz --health-check-interval-seconds 10 \
  --healthy-threshold-count 2 --unhealthy-threshold-count 2 --matcher HttpCode=200 \
  --query 'TargetGroups[0].TargetGroupArn' --output text)
TG_ING=$(aws elbv2 create-target-group --name $NAME-ingest --protocol HTTP --port 80 --vpc-id $VPC \
  --target-type instance --health-check-path /healthz --health-check-interval-seconds 10 \
  --healthy-threshold-count 2 --unhealthy-threshold-count 2 --matcher HttpCode=200 \
  --query 'TargetGroups[0].TargetGroupArn' --output text)
for tg in $TG_APP $TG_ING; do
  aws elbv2 modify-target-group-attributes --target-group-arn $tg --attributes Key=deregistration_delay.timeout_seconds,Value=30
done
ALB_APP=$(aws elbv2 create-load-balancer --name $NAME-app --type application --scheme internet-facing \
  --subnets <lb-a> <lb-b> <lb-c> --security-groups "$(sg lb-app)" --query 'LoadBalancers[0].LoadBalancerArn' --output text)
aws elbv2 create-listener --load-balancer-arn $ALB_APP --protocol HTTPS --port 443 \
  --certificates CertificateArn=<ACM cert for the app hostname> --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06 \
  --default-actions Type=forward,TargetGroupArn=$TG_APP
# same for the ingest ALB with "$(sg lb-ingest)", the ingest hostname's certificate and $TG_ING
aws elbv2 register-targets --target-group-arn $TG_APP --targets Id=<nano-app-1 id> Id=<nano-app-2 id>
```

- **App health check `/readyz`** (nano 2.0.7+): 200 only while that host's API
  and search are ready; 503 while the upgrade orchestrator drains it. Before
  2.0.7 (one app host) use `/healthz`.
- **Ingest health check `/healthz`**: Vector readiness through the ingest edge.
- **HEC indexer acknowledgements** need the ack poll to reach the ingest host
  that took the event. Through an ALB that holds only with stickiness and a
  sender that keeps cookies. Otherwise send HEC without indexer acks, or put
  an NLB with a TLS listener and source-IP stickiness in front of ingest
  instead (then per-client rate limits key on the NLB's addresses).
- Register targets only after each host's install has succeeded.
- For the internal ingest endpoint the HA guide recommends
  (`load_balancer.ingest_endpoint`), use an internal ALB whose certificate
  chains to the cluster's private CA (import it into ACM), and pass
  `--ingest-lb-address <its DNS name> --ingest-lb-tls-name <cert name>` to
  `plan.py`.

DNS: alias records for both hostnames to their ALBs (Route 53 or the
operator's DNS).

## Terraform starting point (optional)

A sketch only, not a module nano supports. It shows the shape the CLI steps
build; review every value against the plan.

```hcl
# Starting point only: one ClickHouse replica, as planned (repeat per plan row)
resource "aws_instance" "ch_s1r1" {
  ami                    = data.aws_ssm_parameter.ubuntu.value
  instance_type          = "r7i.2xlarge"            # plan: nodes[].instance
  subnet_id              = aws_subnet.private["a"].id
  private_ip             = "10.40.1.12"             # plan: nodes[].address
  vpc_security_group_ids = [aws_security_group.g["clickhouse"].id, aws_security_group.g["ingest"].id]
  metadata_options { http_tokens = "required" }
  root_block_device {
    volume_type = "gp3"
    volume_size = 100
    encrypted   = true
  }
  tags = { "nano-deployment" = var.name, Name = "nano-ch-s1r1" }
}
resource "aws_ebs_volume" "ch_s1r1_data" {
  availability_zone = aws_subnet.private["a"].availability_zone
  type              = "gp3"   # plan: nodes[].disks[]
  size              = 1500
  iops              = 4000
  throughput        = 150
  encrypted         = true
  tags = { "nano-deployment" = var.name }
}
```

## Amazon EKS for the Helm chart

The sections above build VMs for the compose topologies. For the Helm chart
([helm.md](helm.md)) the operator brings an EKS cluster. When they have none,
propose this and create it only after they approve (it costs money from the
first minute). Every command uses their `aws`/`eksctl` session.

A small HA cluster: 3 Availability Zones, a NAT gateway per zone, OIDC for
IRSA, the EBS CSI driver, and **two nodes per zone**. EBS volumes are bound to
their zone: with one node per zone, draining or losing a node leaves that
zone's ClickHouse replica and Keeper member Pending (data safe, no redundancy)
until a node returns to that zone. One managed node group per zone keeps the
count per zone fixed. Size the instance type from the plan
(`size.py --topology helm`). Set `clickhouse.zoneAware: true` (the two
replicas of a shard in different zones, Keeper over three zones) with
`antiAffinity: hard`.

```yaml
# eksctl create cluster -f nano-eks.yaml   (about 15-20 minutes)
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: nano
  region: us-east-1
  version: "1.37"
  tags: {nano-deployment: nano}
availabilityZones: ["us-east-1a", "us-east-1b", "us-east-1c"]
vpc:
  cidr: 10.42.0.0/16
  nat: {gateway: HighlyAvailable}
iam:
  withOIDC: true
addons:
  - name: vpc-cni                 # NetworkPolicy enforcement: set it here, at creation
    configurationValues: '{"enableNetworkPolicy": "true"}'
  - name: coredns
  - name: kube-proxy
  - name: eks-pod-identity-agent
  - name: metrics-server          # Vector HPA from the standard preset up
  - name: aws-ebs-csi-driver
    wellKnownPolicies: {ebsCSIController: true}
managedNodeGroups:               # one group per zone, 2 nodes each
  - name: ng-a
    instanceType: m6i.2xlarge     # x86-64 with AVX2 (ClickHouse)
    minSize: 2
    desiredCapacity: 2
    maxSize: 2                    # 6 nodes in all; no cluster autoscaler
    tags: {nano-deployment: nano}
    volumeSize: 100
    volumeType: gp3
    privateNetworking: true
    availabilityZones: ["us-east-1a"]
  - name: ng-b
    instanceType: m6i.2xlarge     # x86-64 with AVX2 (ClickHouse)
    minSize: 2
    desiredCapacity: 2
    maxSize: 2                    # 6 nodes in all; no cluster autoscaler
    tags: {nano-deployment: nano}
    volumeSize: 100
    volumeType: gp3
    privateNetworking: true
    availabilityZones: ["us-east-1b"]
  - name: ng-c
    instanceType: m6i.2xlarge     # x86-64 with AVX2 (ClickHouse)
    minSize: 2
    desiredCapacity: 2
    maxSize: 2                    # 6 nodes in all; no cluster autoscaler
    tags: {nano-deployment: nano}
    volumeSize: 100
    volumeType: gp3
    privateNetworking: true
    availabilityZones: ["us-east-1c"]
```

A 3-node layout (one per zone) also works but tolerates a node loss
only with reduced redundancy, as above.

**NetworkPolicy on an existing cluster.** The `vpc-cni` line above turns on
the network policy agent (VPC CNI v1.14+) at creation. On an existing
cluster, never run a bare `aws eks update-addon ... --configuration-values`:
eksctl created the add-on with a service account role, a bare update drops
it, and the new `aws-node` pods crash-loop (`MissingIAMPermissions:
ec2:DescribeNetworkInterfaces`) while the add-on sits in UPDATING with no
health issue (seen in a 2.0.11 test). Ask first, then:

```bash
ROLE=$(aws eks describe-addon --cluster-name nano --addon-name vpc-cni --query 'addon.serviceAccountRoleArn' --output text)
aws eks update-addon --cluster-name nano --addon-name vpc-cni \
  --service-account-role-arn "$ROLE" --resolve-conflicts PRESERVE \
  --configuration-values '{"enableNetworkPolicy": "true"}'     # drop --service-account-role-arn if $ROLE is None
aws eks wait addon-active --cluster-name nano --addon-name vpc-cni
kubectl -n kube-system rollout status daemonset/aws-node --timeout=10m
```

If an `aws-node` pod crash-loops: `kubectl -n kube-system annotate sa aws-node
eks.amazonaws.com/role-arn=<role> --overwrite`, delete that pod, and rerun the
update with the role.

Then, in order (each is a hard stop for the chart):

1. **Default StorageClass.** EKS ships none that the EBS CSI driver serves.

   ```bash
   kubectl apply -f - <<'YAML'
   apiVersion: storage.k8s.io/v1
   kind: StorageClass
   metadata:
     name: gp3
     annotations: {storageclass.kubernetes.io/is-default-class: "true"}
   provisioner: ebs.csi.aws.com
   parameters:
     type: gp3
     tagSpecification_1: "nano-deployment=nano"
   volumeBindingMode: WaitForFirstConsumer
   allowVolumeExpansion: true
   YAML
   ```

2. **Gateway API.** The standard CRDs (`kubectl apply -f
   https://github.com/kubernetes-sigs/gateway-api/releases/download/<v>/standard-install.yaml`),
   then the AWS Load Balancer Controller v2.13+ with IRSA (its IAM policy from
   the controller release), its gateway CRDs (`config/crd/gateway/gateway-crds.yaml`
   of the same controller release) and the Gateway API feature gate
   (`--set controllerConfig.featureGates.ALBGatewayAPI=true` on the controller
   chart). Pin the controller chart (`--version`) and tag what it creates
   (`--set defaultTags.nano-deployment=nano`: the ALBs, target groups and
   security groups). Create the GatewayClass `values-aws.yaml` expects:

   ```bash
   kubectl apply -f - <<'YAML'
   apiVersion: gateway.networking.k8s.io/v1
   kind: GatewayClass
   metadata: {name: aws-alb}
   spec: {controllerName: gateway.k8s.aws/alb}
   YAML
   ```

   The chart renders a `TargetGroupConfiguration` with `targetType: ip` for
   both backends (2.0.10+), so the controller's default instance targets need
   no change. On chart 2.0.9 and earlier, install the controller with
   `--set defaultTargetType=ip`, or the ALBs never get targets ("TargetGroup
   port is empty"). On controller v3.x set
   `gateway.aws.crdApiVersion: gateway.k8s.aws/v1` to silence its v1beta1
   deprecation warning.

3. **Certificates.** `values-aws.yaml` terminates TLS on the ALBs with ACM
   (`tls.mode: cloud-managed`): an ACM certificate in the cluster's region
   for the app hostname and one for the ingest hostname (one certificate with
   both names is fine), set as `tls.aws.appCertificateArn` and
   `tls.aws.ingestCertificateArn`. The operator needs a domain they control;
   after install, CNAME both hostnames to the ALB names
   (`kubectl -n nano get gateway`).

   **Restrict exposure** (ask; matches the docs' "Restrict exposure"): both
   ALBs are internet-facing and open to 0.0.0.0/0 by default. Set
   `gateway.aws.sourceRanges.app` (users' and admins' CIDRs) and
   `gateway.aws.sourceRanges.ingest` (the senders' CIDRs), or
   `gateway.aws.scheme: internal` when everyone reaches the VPC privately.

4. **PostgreSQL.** For production, RDS for PostgreSQL 16+ (Multi-AZ for HA)
   in the cluster VPC, its security group open on 5432 to the node security
   group; `postgresql.mode: external`, `sslmode: require`, the password in a
   Secret (`postgresql.external.passwordSecret`). See
   [Managed PostgreSQL (RDS)](#managed-postgresql-rds).

5. **Registry credential.** The Self-run pull credential lasts one hour; the
   chart's `registryCredentialRefresh` CronJob keeps `nano-registry` fresh (see
   [helm.md](helm.md)). Do not disable it unless images come from a mirror
   (`global.imageRegistry`, e.g. ECR).

Teardown (only on request), in this order, so nothing hangs on a finalizer:
1. `helm uninstall nano -n nano` (deletes the Gateways); wait until
   `kubectl -n nano get gateway` lists none and the ALBs are gone.
2. `kubectl delete gatewayclass aws-alb` while the AWS Load Balancer
   Controller is still running (after it, the class hangs on the
   `gateway.k8s.aws/gatewayclass` finalizer).
3. Delete the PVCs, `nano-secrets`, `vector-source-credentials` and the
   namespace; then `helm uninstall aws-load-balancer-controller -n kube-system`.
4. `eksctl delete cluster -f nano-eks.yaml --wait`, the RDS instance (and its
   subnet and security groups), the ACM certificate and the controller's IAM
   policy.

## Managed PostgreSQL (RDS)

The production database for the Helm chart (`postgresql.mode: external`).
The migrator checks the version and extensions before it applies anything;
run `scripts/pg-preflight.py` first so a gap shows before `helm install`.

| Item | Requirement |
|---|---|
| Version | PostgreSQL 16 or newer (16, 17, 18 tested). RDS PostgreSQL 16 works from nano 2.0.11; 2.0.10 and earlier need 17+ |
| Extensions | `pg_trgm`, `pgcrypto`, `uuid-ossp`. All are on RDS's supported list and trusted, so the database owner creates them. Nothing to do unless the parameter group sets `rds.allowed_extensions`: then add the three (the default `*` allows them) |
| Parameters | None required. Default `rds.force_ssl=1` is fine (`sslmode: require`). Allow at least 200 connections (about 20 per nano pod); every class from `db.m7g.large` up does by default |
| Network | Private subnets of the EKS VPC, `--no-publicly-accessible`, security group allowing 5432 from the node security group only |
| HA | Multi-AZ DB instance (`--multi-az`, synchronous standby in another AZ, about 60-120 s failover), or a Multi-AZ DB cluster. Single-AZ is a single point of failure |

```bash
aws rds create-db-subnet-group --db-subnet-group-name $NAME-pg \
  --db-subnet-group-description "nano $NAME" --subnet-ids <private subnet ids>
aws rds create-db-instance --db-instance-identifier $NAME-pg \
  --engine postgres --engine-version 17 --db-instance-class db.m7g.large \
  --allocated-storage 50 --storage-type gp3 --storage-encrypted --multi-az \
  --db-subnet-group-name $NAME-pg --vpc-security-group-ids <db sg> --no-publicly-accessible \
  --master-username nanoadmin --manage-master-user-password \
  --backup-retention-period 7 --tags Key=nano-deployment,Value=$NAME
```

`--manage-master-user-password` keeps the admin password in Secrets Manager;
never pass `--master-user-password` on a command line.

Create the role and database as the admin user. The instance is private, so
reach it from a one-off pod in the cluster (passwords from a temporary
Secret, never on a command line; the docs' "Reaching a private RDS or Azure
server" has the same recipe). The admin password is in Secrets Manager
(`aws secretsmanager get-secret-value --secret-id <MasterUserSecret arn>
--query SecretString --output text | python3 -c 'import json,sys;
print(json.load(sys.stdin)["password"], end="")' > pg-admin-password.txt`);
the operator writes the nano password to `pg-password.txt`:

```bash
kubectl create namespace nano --dry-run=client -o yaml | kubectl apply -f -
kubectl -n nano create secret generic pg-bootstrap \
  --from-file=admin=./pg-admin-password.txt --from-file=nano=./pg-password.txt
kubectl -n nano run pg-bootstrap --rm -i --restart=Never --image=postgres:17-alpine --overrides='
{"spec": {"containers": [{"name": "pg-bootstrap", "image": "postgres:17-alpine", "stdin": true,
  "command": ["sh", "-c", "PGPASSWORD=$(cat /s/admin) exec psql -v ON_ERROR_STOP=1 \"host=<endpoint> user=nanoadmin dbname=postgres sslmode=require\" -f -"],
  "volumeMounts": [{"name": "s", "mountPath": "/s", "readOnly": true}]}],
  "volumes": [{"name": "s", "secret": {"secretName": "pg-bootstrap"}}]}}' <<'SQL'
\set pw `cat /s/nano`
CREATE ROLE nanosiem LOGIN;
ALTER ROLE nanosiem PASSWORD :'pw';
GRANT nanosiem TO CURRENT_USER;
CREATE DATABASE nanosiem OWNER nanosiem;
\connect nanosiem
ALTER SCHEMA public OWNER TO nanosiem;
SQL
kubectl -n nano delete secret pg-bootstrap
```

From a host that already reaches the database (a bastion), the same SQL works
in interactive `psql`, with `\password nanosiem` instead of the `\set` and
`ALTER ROLE` lines:

```sql
CREATE ROLE nanosiem LOGIN;
\password nanosiem
GRANT nanosiem TO nanoadmin;          -- PostgreSQL 16+: needed before ... OWNER nanosiem
CREATE DATABASE nanosiem OWNER nanosiem;
\connect nanosiem
ALTER SCHEMA public OWNER TO nanosiem;
```

The last two lines make sure the nano user can create tables in schema
`public`. PostgreSQL 15 and newer no longer grant that to every role; on RDS
the database owner normally has it already (through `pg_database_owner`), so
this is a no-op there, but a database created another way fails the first
migration with `permission denied for schema public`. `pg-preflight.py`
checks it (`FAIL schema` prints the fix). The owner can create the three
trusted extensions itself. Use a URL-safe
password (it is interpolated into `DATABASE_URL`), then check with
`scripts/pg-preflight.py` ([helm.md](helm.md#step-0-preflight-read-only)).
