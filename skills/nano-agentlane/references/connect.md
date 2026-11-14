# Connecting to Agent Lane

You need two things from a nano admin, both from **Settings → Agent Lane**:

- **The Agent Lane URL.** It is HTTPS, on port **8444** unless the install
  changed it, for example `https://nano.example.com:8444`. It is specific to
  each install.
- **A token** of the form `nal_<id>_<secret>`. It is shown once, when it's
  created. Each token has an expiry date and an IP allow-list.

The listener speaks **HTTPS only** (ClickHouse's HTTP interface over TLS).
Use an HTTP client: curl, Python `clickhouse-connect` or the JS
`@clickhouse/client`. The native `clickhouse-client` uses ClickHouse's TCP
protocol, which Agent Lane does not expose, so it can't connect.

## Keep the token out of sight

Get the token into your shell without it landing in a file you didn't
mean to create or in shell history. Either the operator saved it to a file
(mode 0600) and you read it from there, or you paste it at a silent prompt:

```bash
export NAL_URL="https://nano.example.com:8444"
export NAL_HOST="nano.example.com"           # the host part of NAL_URL
read -rs NAL_TOKEN && export NAL_TOKEN       # paste the token; nothing is echoed or saved
# or: export NAL_TOKEN="$(cat ~/.config/nano/agentlane.token)"
```

Never echo `$NAL_TOKEN`, never put it on a command line in plain text, and
never write it into a script, notebook or commit.

## Split the token into user and password

The token carries both halves of a ClickHouse login:

| Token part | ClickHouse login |
|---|---|
| `nal_` | prefix, dropped |
| `<id>` (lowercase letters and digits) | user `agentlane_<id>` |
| `<secret>` (everything after the second `_`) | password |

The secret is base64url, so it can itself contain `_` and `-`. **Split only at
the first two underscores.**

```text
nal_7k2m9q4x8w_Zx3-Qp_9vT...    →    user     agentlane_7k2m9q4x8w
                                       password Zx3-Qp_9vT...
```

## Write a netrc file for curl (once)

curl reads the login from a netrc file, so the password never appears on a
command line or in the process list. `printf` is a shell builtin, so the
secret below is never a process argument, and the variables keep it out of
history. `umask 077` makes the file 0600 from the start:

```bash
mkdir -p ~/.config/nano
(
  umask 077
  rest="${NAL_TOKEN#nal_}"
  printf 'machine %s login agentlane_%s password %s\n' \
    "$NAL_HOST" "${rest%%_*}" "${rest#*_}" > ~/.config/nano/agentlane.netrc
)
export NAL_NETRC=~/.config/nano/agentlane.netrc
```

Every curl example below passes `--netrc-file "$NAL_NETRC"`. Never use
`-u user:password`: it shows the password to anyone who can list processes
and can land in shell history. (A curl config file with `user = "…"`, mode
0600, passed with `-K`, works the same way.) Delete the file when the token
is revoked or expires. The Python and JS examples read `NAL_TOKEN` from the
environment instead; if you only use curl, `unset NAL_TOKEN` now.

## TLS

If the install's certificate comes from a public CA, there's nothing to do.
If it uses a private CA, get the CA certificate (PEM) from the admin and trust
it for this connection only:

- curl: `--cacert /path/to/nano-ca.pem`
- Python: `ca_cert='/path/to/nano-ca.pem'`
- JS: `tls: { ca_cert: fs.readFileSync('/path/to/nano-ca.pem') }`

Never turn verification off (`-k`, `verify=False`,
`rejectUnauthorized: false`). If the certificate doesn't match the host name,
report it to the admin.

## Connect check

Run this first. It should print your user, `1` (read-only) and `agentlane`
(the workload).

```bash
echo "SELECT currentUser(), getSetting('readonly'), getSetting('workload') FORMAT TSV" |
  curl -sS --fail-with-body --cacert "$NAL_CA" --netrc-file "$NAL_NETRC" \
    "$NAL_URL/?log_comment=$NAL_SESSION" --data-binary @-
```

Leave out `--cacert "$NAL_CA"` when the certificate comes from a public CA.
Set `NAL_SESSION` to your agent session id once per session.

If it fails:

| Error | Meaning |
|---|---|
| `Code: 516 … AUTHENTICATION_FAILED` | Wrong user/password split (or the netrc `machine` doesn't match the URL's host), expired or revoked token, or your IP is not on the token's allow-list. Ask the admin; don't retry in a loop. |
| Connection refused or timeout | Wrong URL or port, or a firewall between you and the lane. |
| Certificate error | Private CA not trusted (see TLS above), or a host name mismatch. |

## curl

Send the SQL as the request body and values as `param_<name>` URL
parameters. `--data-urlencode` with `-G` would put the SQL in the URL; keep it
in the body instead.

```bash
curl -sS --fail-with-body --cacert "$NAL_CA" --netrc-file "$NAL_NETRC" \
  "$NAL_URL/?log_comment=$NAL_SESSION&param_ip=203.0.113.66&default_format=JSONCompact" \
  --data-binary @- <<'SQL'
SELECT `src_endpoint.ip` AS src, count() AS events
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND `dst_endpoint.ip` = {ip:String}
GROUP BY src
ORDER BY events DESC
LIMIT 20
SQL
```

URL-encode parameter values that contain special characters (for an array:
`param_ips=%5B%27203.0.113.66%27%5D` for `['203.0.113.66']`). A failed query
returns a non-200 status and a `Code: NNN` message, which `--fail-with-body`
turns into a non-zero exit.

## Python (clickhouse-connect)

```python
import os
import clickhouse_connect

_, token_id, secret = os.environ["NAL_TOKEN"].split("_", 2)  # split at the first two '_'
client = clickhouse_connect.get_client(
    interface="https",
    host="nano.example.com",
    port=8444,
    username=f"agentlane_{token_id}",
    password=secret,
    ca_cert=os.environ.get("NAL_CA"),          # omit for a public CA
    settings={"log_comment": os.environ["NAL_SESSION"]},
)
result = client.query(
    """
    SELECT class_name, count() AS events
    FROM nanosiem.ocsf_logs
    WHERE timestamp >= now() - INTERVAL 24 HOUR
      AND `src_endpoint.ip` = {ip:String}
    GROUP BY class_name
    ORDER BY events DESC
    LIMIT 20
    """,
    parameters={"ip": "10.0.0.10"},
)
print(result.result_rows)
```

## JavaScript / TypeScript (@clickhouse/client)

```ts
import { readFileSync } from "node:fs";
import { createClient } from "@clickhouse/client";

const m = /^nal_([a-z0-9]+)_(.+)$/.exec(process.env.NAL_TOKEN ?? "");
if (!m) throw new Error("NAL_TOKEN is not an Agent Lane token");

const client = createClient({
  url: process.env.NAL_URL,                     // https://nano.example.com:8444
  username: `agentlane_${m[1]}`,
  password: m[2],
  tls: process.env.NAL_CA ? { ca_cert: readFileSync(process.env.NAL_CA) } : undefined,
  clickhouse_settings: { log_comment: process.env.NAL_SESSION },
});

const rs = await client.query({
  query: `SELECT source_type, count() AS events
          FROM nanosiem.ocsf_logs
          WHERE timestamp >= now() - INTERVAL 24 HOUR
          GROUP BY source_type
          ORDER BY events DESC
          LIMIT {n:UInt32}`,
  query_params: { n: 20 },
  format: "JSONEachRow",
});
console.log(await rs.json());
await client.close();
```

## What you can change per query

Only these settings are accepted. Anything else is refused (Code 452 or 164):

- output: the `FORMAT` clause, `default_format`, `date_time_output_format`,
  `output_format_json_quote_64bit_integers`,
  `output_format_json_named_tuples_as_objects` and `enable_http_compression`;
- `log_comment` (set it to your session id);
- `session_timezone`;
- lowering, never raising, `max_execution_time` (at most 60) and
  `max_result_rows` (at most 100000).

One statement per request. Multi-statement bodies are refused.
