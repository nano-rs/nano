# Agent skills

Skills in the open [Agent Skills](https://agentskills.io) format, for coding
agents such as Claude Code and Codex.

| Skill | What it does |
|---|---|
| [`nano-deploy`](nano-deploy/SKILL.md) | Sizes, deploys, verifies and operates nano Self-run (enterprise, licensed) on your own hosts: single node, 3-node HA (Compose role split), a fully highly available cluster of N VMs (yours, or new ones on AWS, Azure or GCP) laid out from your data volume, or Kubernetes (Helm). It runs a read-only preflight first, asks before every change (and before creating any cloud resource) and never prints secrets. |

## Install

Claude Code (personal skills directory):

```bash
mkdir -p ~/.claude/skills && curl -fsSL https://github.com/nano-rs/nano/archive/refs/heads/main.tar.gz \
  | tar -xz -C ~/.claude/skills --strip-components=2 nano-main/skills/nano-deploy
```

Any agent with Agent Skills support, through the open `skills` installer:

```bash
npx skills add nano-rs/nano --skill nano-deploy
```

For an agent without skill support, copy the folder anywhere and tell the
agent: *"Read `nano-deploy/SKILL.md` and follow it."*

Guide: [Deploy with your AI agent](https://nano.rs/docs/getting-started/deploy-with-ai-agent/).
