#!/usr/bin/env bash
# Seed test topics + sample events for the NAN-884 Kafka audit.
#
# Topics align with the test matrix in the Linear ticket:
#   T-1  / T-15  nano.logs.apache.access  - plaintext anonymous
#   T-9          nano.logs.sysmon         - sets headers.source_type so router picks it up
#   T-10         nano.audit.events        - topic-name routing target
#   T-11         nano.logs.json           - JSON body with event_type for content-sniff
#   K-8          nano.logs.app.access.*   - several topics to exercise regex topic patterns
#
# Usage:
#   dev/kafka/seed.sh           # create topics + seed a few records on each
#   dev/kafka/seed.sh produce HEADER nano.logs.sysmon source_type=sysmon '{"foo":"bar"}'
#   dev/kafka/seed.sh consume nano.audit.events earliest

set -euo pipefail

CONTAINER=nano-kafka-test
BOOTSTRAP_PLAIN=kafka:9092
BOOTSTRAP_SASL=kafka:9093
CLIENT_CONFIG_SASL=/tmp/sasl-plain-client.properties

TOPICS=(
  nano.logs.apache.access
  nano.logs.sysmon
  nano.audit.events
  nano.logs.json
  nano.logs.app.access.web
  nano.logs.app.access.api
)

ensure_sasl_client_props() {
  docker exec "$CONTAINER" sh -c 'cat > '"$CLIENT_CONFIG_SASL"' <<EOF
security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="admin" password="admin-secret";
EOF'
}

create_topics() {
  for t in "${TOPICS[@]}"; do
    docker exec "$CONTAINER" /opt/kafka/bin/kafka-topics.sh \
      --bootstrap-server "$BOOTSTRAP_PLAIN" \
      --create --if-not-exists \
      --topic "$t" \
      --partitions 3 --replication-factor 1
  done
  echo "--- topics now on broker ---"
  docker exec "$CONTAINER" /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server "$BOOTSTRAP_PLAIN" --list
}

produce_plain() {
  local topic="$1" payload="$2"
  printf '%s\n' "$payload" | docker exec -i "$CONTAINER" \
    /opt/kafka/bin/kafka-console-producer.sh \
    --bootstrap-server "$BOOTSTRAP_PLAIN" \
    --topic "$topic"
}

# Produce with a Kafka record header. Header format: name=value
produce_with_header() {
  local topic="$1" header_kv="$2" payload="$3"
  printf '%s\t%s\n' "$header_kv" "$payload" | docker exec -i "$CONTAINER" \
    /opt/kafka/bin/kafka-console-producer.sh \
    --bootstrap-server "$BOOTSTRAP_PLAIN" \
    --topic "$topic" \
    --property parse.headers=true \
    --property headers.delimiter=$'\t' \
    --property headers.separator=, \
    --property headers.key.separator==
}

seed() {
  echo '--- T-1 plaintext apache lines ---'
  produce_plain nano.logs.apache.access '127.0.0.1 - - [20/May/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612'
  produce_plain nano.logs.apache.access '10.0.0.5 - - [20/May/2026:10:00:01 +0000] "POST /api HTTP/1.1" 201 33'

  echo '--- T-9 sysmon with headers.source_type ---'
  produce_with_header nano.logs.sysmon 'source_type=sysmon' \
    '{"event_id":1,"image":"C:\\Windows\\System32\\cmd.exe"}'
  produce_with_header nano.logs.sysmon 'source_type=sysmon' \
    '{"event_id":3,"src_ip":"10.0.0.5","dst_ip":"1.1.1.1"}'

  echo '--- T-10 audit events (topic-name routing) ---'
  produce_plain nano.audit.events '{"action":"user_login","user":"alice","result":"success"}'
  produce_plain nano.audit.events '{"action":"file_delete","user":"bob","path":"/etc/passwd"}'

  echo '--- T-11 content-sniff (event_type in JSON body) ---'
  produce_plain nano.logs.json '{"event_type":"firewall","src_ip":"203.0.113.1","action":"drop"}'
  produce_plain nano.logs.json '{"event_type":"proxy","src_ip":"10.0.0.7","url":"https://example.com"}'

  echo '--- K-8 regex topic candidates ---'
  produce_plain nano.logs.app.access.web '{"app":"web","status":200}'
  produce_plain nano.logs.app.access.api '{"app":"api","status":500}'
}

consume() {
  local topic="$1" reset="${2:-latest}"
  docker exec -it "$CONTAINER" /opt/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server "$BOOTSTRAP_PLAIN" \
    --topic "$topic" \
    --from-beginning \
    --max-messages 20 \
    --property print.headers=true \
    --property print.key=true \
    --property print.timestamp=true
}

case "${1:-all}" in
  topics)  create_topics ;;
  produce) shift; produce_with_header "$@" ;;
  consume) shift; consume "$@" ;;
  reset)   ensure_sasl_client_props ;;
  all)
    ensure_sasl_client_props
    create_topics
    seed
    ;;
  *) echo "usage: $0 [all|topics|produce|consume|reset]" >&2; exit 2 ;;
esac
