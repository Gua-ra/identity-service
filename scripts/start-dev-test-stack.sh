#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.test.yml"
SYNAPSE_DATA_DIR="$REPO_ROOT/docker/synapse/data"
ENV_SNAPSHOT="$REPO_ROOT/.env.identity-service"

ADMIN_USER="identity-admin"
ADMIN_PASS="ChangeMe123!"
HOMESERVER_URL="http://localhost:8008"
MATRIX_HOME_DOMAIN="dev.local"

function require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: required command '$1' not found on PATH" >&2
    exit 1
  fi
}

for cmd in docker curl openssl jq; do
  require_cmd "$cmd"
done

mkdir -p "$SYNAPSE_DATA_DIR"

echo "Starting development dependencies with docker compose..."
docker compose -f "$COMPOSE_FILE" up -d --remove-orphans >/dev/null

echo "Waiting for Synapse to become available..."
ATTEMPTS=0
until curl -sf "$HOMESERVER_URL/_matrix/client/versions" >/dev/null; do
  ATTEMPTS=$((ATTEMPTS + 1))
  if docker compose -f "$COMPOSE_FILE" ps synapse >/dev/null 2>&1; then
    STATUS=$(docker compose -f "$COMPOSE_FILE" ps --format '{{.State}}' synapse 2>/dev/null || echo "")
    if [ "$STATUS" = "exited" ] || [ "$STATUS" = "dead" ]; then
      echo "Synapse container exited unexpectedly. Showing last 40 log lines:" >&2
      docker compose -f "$COMPOSE_FILE" logs --tail=40 synapse >&2 || true
      exit 1
    fi
  fi
  if [ "$ATTEMPTS" -gt 60 ]; then
    echo "Synapse did not become ready in time" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=40 synapse >&2 || true
    exit 1
  fi
  sleep 2
done

echo "Ensuring Synapse admin user exists..."
set +e
docker compose -f "$COMPOSE_FILE" exec -T synapse register_new_matrix_user \
  -u "$ADMIN_USER" \
  -p "$ADMIN_PASS" \
  --admin \
  -a "http://localhost:8008" \
  -c /data/homeserver.yaml >/dev/null 2>&1
set -e

LOGIN_RESPONSE=$(curl -sfS -X POST "$HOMESERVER_URL/_matrix/client/v3/login" \
  -H 'Content-Type: application/json' \
  -d "{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"$ADMIN_USER\"},\"password\":\"$ADMIN_PASS\"}" ) || {
  echo "Failed to call Synapse login endpoint" >&2
  exit 1
}

ADMIN_TOKEN=$(printf '%s' "$LOGIN_RESPONSE" | jq -r '.access_token // empty')

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
  echo "Failed to obtain Synapse admin access token" >&2
  exit 1
fi

PEPPER_FILE="$REPO_ROOT/docker/.identity-pepper"
if [ -f "$PEPPER_FILE" ]; then
  DIRECTORY_PEPPER=$(cat "$PEPPER_FILE")
else
  DIRECTORY_PEPPER=$(openssl rand -hex 16)
  echo "$DIRECTORY_PEPPER" > "$PEPPER_FILE"
fi

read -r -d '' ENV_EXPORTS <<EOS || true
export IDENTITY_MATRIX_ADMIN_API_BASE_URL=$HOMESERVER_URL
export IDENTITY_MATRIX_CLIENT_API_BASE_URL=$HOMESERVER_URL
export IDENTITY_MATRIX_HOME_DOMAIN=$MATRIX_HOME_DOMAIN
export IDENTITY_MATRIX_ADMIN_TOKEN=$ADMIN_TOKEN
export IDENTITY_MATRIX_LOCALPART_PREFIX=gua
export IDENTITY_DIRECTORY_PEPPER=$DIRECTORY_PEPPER
export SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/identity
export SPRING_DATASOURCE_USERNAME=identity
export SPRING_DATASOURCE_PASSWORD=identity
export SPRING_DATASOURCE_DRIVER_CLASS_NAME=org.postgresql.Driver
export SPRING_DATA_REDIS_HOST=localhost
export SPRING_DATA_REDIS_PORT=6379
EOS

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  eval "$ENV_EXPORTS"
  echo "Development environment variables exported in current shell."
else
  printf '%s\n' "$ENV_EXPORTS" > "$ENV_SNAPSHOT"
  echo "Environment variables written to $ENV_SNAPSHOT"
  echo "Run 'source $ENV_SNAPSHOT' to load them into your shell or copy them into your IDE runtime profile."
fi
