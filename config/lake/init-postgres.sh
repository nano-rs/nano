#!/bin/sh
set -eu

required() {
  name=$1
  eval "value=\${$name:-}"
  if [ -z "$value" ]; then
    echo "$name is required" >&2
    exit 1
  fi
}

for name in \
  PGHOST PGPORT PGUSER PGPASSWORD \
  NANO_LAKEKEEPER_DB_PASSWORD \
  NANO_LAKEKEEPER_OIDC_DB_PASSWORD \
  NANO_LAKEKEEPER_OPENFGA_DB_PASSWORD
do
  required "$name"
done

role_exists() {
  psql -v ON_ERROR_STOP=1 -d postgres -tAc \
    "SELECT 1 FROM pg_roles WHERE rolname = '$1'" | grep -q 1
}

database_exists() {
  psql -v ON_ERROR_STOP=1 -d postgres -tAc \
    "SELECT 1 FROM pg_database WHERE datname = '$1'" | grep -q 1
}

ensure_role() {
  role=$1
  password=$2
  if role_exists "$role"; then
    psql -v ON_ERROR_STOP=1 -d postgres \
      --set=role_password="$password" >/dev/null <<SQL
ALTER ROLE $role WITH LOGIN PASSWORD :'role_password';
SQL
  else
    psql -v ON_ERROR_STOP=1 -d postgres \
      --set=role_password="$password" >/dev/null <<SQL
CREATE ROLE $role WITH LOGIN PASSWORD :'role_password';
SQL
  fi
}

ensure_database() {
  database=$1
  owner=$2
  if ! database_exists "$database"; then
    createdb --owner="$owner" "$database"
  fi
  psql -v ON_ERROR_STOP=1 -d postgres \
    -c "ALTER DATABASE $database OWNER TO $owner" >/dev/null
}

ensure_role lakekeeper "$NANO_LAKEKEEPER_DB_PASSWORD"
ensure_role lakekeeper_oidc "$NANO_LAKEKEEPER_OIDC_DB_PASSWORD"
ensure_role lakekeeper_openfga "$NANO_LAKEKEEPER_OPENFGA_DB_PASSWORD"

ensure_database nanosiem_lakekeeper lakekeeper
ensure_database nanosiem_lakekeeper_oidc lakekeeper_oidc
ensure_database nanosiem_lakekeeper_openfga lakekeeper_openfga

echo "Nano lake PostgreSQL roles and databases are ready"
