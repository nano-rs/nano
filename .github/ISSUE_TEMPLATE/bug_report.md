---
name: Bug report
about: Report something that's broken or behaving unexpectedly
title: "[bug] "
labels: bug
assignees: ''
---

## What's broken

A short, specific description. (e.g., "Search returns 0 results for `error`
when message column clearly contains the token.")

## Reproduce

Minimal steps:

1. ...
2. ...
3. ...

If a query, paste the exact nPL:

```
your | query | here
```

## Expected vs actual

- **Expected:** ...
- **Actual:** ...

## Environment

- nano version (commit SHA or `:vX.Y.Z` tag): 
- Edition: open / enterprise
- Deployment: docker compose / k8s / bare cargo
- ClickHouse version: 
- Postgres version: 
- Browser (if web-side bug): 

## Logs / screenshots

Paste relevant `nanosiem-api` / `nanosiem-search` log lines. Redact anything
sensitive (IPs, hostnames, user data).

```
log lines here
```

## Anything else

- Did this work in a previous version? Which one?
- Is the bug reproducible 100% of the time, or intermittent?
- Any workaround you've found?

---

**Security issues:** please do **not** file as public bug reports. See
[SECURITY.md](../../SECURITY.md) — email security@nano.rs instead.
