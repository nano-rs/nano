#!/bin/bash
# nano public benchmark host prep: Docker from Docker's apt repo, tools.
set -eux
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl jq python3 sysstat chrony
curl -fsSL https://get.docker.com | sh
usermod -aG docker ubuntu
systemctl enable --now docker sysstat
touch /var/lib/nano-bench-ready
