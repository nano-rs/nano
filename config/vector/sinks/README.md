# Vector sinks (optional)

The dev `docker-compose.yml` loads this directory with
`--config-dir /etc/vector/sinks`. It is empty by default: the lake sinks are
generated (`sources/parsers/_ocsf_sink.toml`) or static
(`04-otlp-lake-sink.toml`). Drop an extra `*.toml` sink here for local
experiments only; nothing in this directory ships.
