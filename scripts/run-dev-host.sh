#!/usr/bin/env bash
# Runs the broker on the host against the infrastructure of an mcp-platform-dev stack that is already up
# (Keycloak, Redis, OpenBao, mocks). The broker gets its own PostgreSQL: a container started here and removed
# on exit, because the broker's migrations must not run against the database of the stack's own broker.
# Set MCP_DB_URL, MCP_DB_USER and MCP_DB_PASSWORD to use a database of your own instead.
#
# Needs: JAVA_HOME on JDK 25, docker (for the default database), MCP_PLATFORM_DEV pointing at the
# mcp-platform-dev checkout (default: ../mcp-platform-dev next to this repository).
# Ports (ws-06 range 18710-18719): broker MCP_BROKER_PORT (18710), database MCP_BROKER_DB_PORT (18711).
#
# Without a running gateway the internal JWT keys come from the published TEST JWKS of mcp-contracts and
# test kids are allowed, so resolve can be called with tokens signed by the test keys. Dev only.
set -euo pipefail

die() { echo "run-dev-host: $*" >&2; exit 1; }

here="$(cd "$(dirname "$0")/.." && pwd)"
dev="${MCP_PLATFORM_DEV:-$here/../mcp-platform-dev}"
contracts="${MCP_CONTRACTS:-$here/../mcp-contracts}"
jar="$here/target/mcp-credential-broker.jar"
java_bin="${JAVA_HOME:+$JAVA_HOME/bin/}java"

[[ -d "$dev" ]] || die "mcp-platform-dev not found at $dev: set MCP_PLATFORM_DEV to its checkout"
[[ -f "$dev/.secrets/dev.env" ]] || die "no $dev/.secrets/dev.env: start the stack first (make up in $dev)"
[[ -f "$jar" ]] || die "no $jar: run ./mvnw -B package -DskipTests first"
java_major="$("$java_bin" -version 2>&1 | sed -n '1s/.*version "\([0-9]*\).*/\1/p')"
[[ "${java_major:-0}" -ge 25 ]] || die "JDK 25 needed, '$java_bin' is ${java_major:-unknown}: set JAVA_HOME"

port="${MCP_BROKER_PORT:-18710}"
if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
  die "port $port is taken: set MCP_BROKER_PORT (ws-06 range 18710-18719)"
fi

db_container=""
cleanup() {
  if [[ -n "$db_container" ]]; then
    docker rm -f "$db_container" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ -z "${MCP_DB_URL:-}" ]]; then
  command -v docker >/dev/null || die "docker not found: set MCP_DB_URL, MCP_DB_USER and MCP_DB_PASSWORD to use another database"
  db_port="${MCP_BROKER_DB_PORT:-18711}"
  if lsof -nP -iTCP:"$db_port" -sTCP:LISTEN >/dev/null 2>&1; then
    die "port $db_port is taken: set MCP_BROKER_DB_PORT (ws-06 range 18710-18719)"
  fi
  db_container="mcp-broker-host-pg-$db_port"
  MCP_DB_PASSWORD="$(openssl rand -hex 16)"
  MCP_DB_USER=broker
  docker rm -f "$db_container" >/dev/null 2>&1 || true
  docker run -d --rm --name "$db_container" -e POSTGRES_DB=broker -e POSTGRES_USER=broker \
    -e POSTGRES_PASSWORD="$MCP_DB_PASSWORD" -p "127.0.0.1:$db_port:5432" \
    "${MCP_BROKER_DB_IMAGE:-postgres:18.6-alpine}" >/dev/null || die "could not start the database container"
  for _ in $(seq 1 60); do
    docker exec "$db_container" pg_isready -h 127.0.0.1 -U broker -d broker >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec "$db_container" pg_isready -h 127.0.0.1 -U broker -d broker >/dev/null 2>&1 || die "the database did not become ready"
  MCP_DB_URL="jdbc:postgresql://localhost:$db_port/broker"
  echo "run-dev-host: own database in container $db_container (port $db_port), removed on exit" >&2
else
  : "${MCP_DB_USER:?set MCP_DB_USER with MCP_DB_URL}" "${MCP_DB_PASSWORD:?set MCP_DB_PASSWORD with MCP_DB_URL}"
fi

set -a
# shellcheck disable=SC1091
. "$dev/.secrets/dev.env"
set +a

export MCP_DB_URL MCP_DB_USER MCP_DB_PASSWORD
export MCP_BROKER_PORT="$port"
export MCP_TLS_KEYSTORE="$dev/certs/mcp-credential-broker/keystore.p12"
export MCP_TLS_TRUSTSTORE="$dev/certs/ca/truststore.p12"
export MCP_TLS_STORE_PASSWORD="$TLS_STORE_PASSWORD"
export MCP_REDIS_HOST=localhost MCP_REDIS_PORT=16379 MCP_REDIS_USER=broker MCP_REDIS_PASSWORD="$REDIS_BROKER_PASSWORD"
export MCP_BAO_ADDR=http://localhost:18200 MCP_BAO_ROLE_ID="$BAO_BROKER_ROLE_ID" MCP_BAO_SECRET_ID="$BAO_BROKER_SECRET_ID"
export MCP_OIDC_ISSUER=http://localhost:18080/realms/corp
export MCP_OIDC_JWKS_URI=http://localhost:18080/realms/corp/protocol/openid-connect/certs
export MCP_JIRA_URL=http://localhost:18081
export MCP_PORTAL_URL="${MCP_PORTAL_URL:-http://localhost:18090}"
# OpenBao, Keycloak and the mocks of the dev stack speak plain HTTP.
export MCP_ALLOW_PLAIN_HTTP=true
if [[ -z "${MCP_GATEWAY_JWKS_URI:-}" ]]; then
  export MCP_GATEWAY_JWKS_FILE="${MCP_GATEWAY_JWKS_FILE:-$contracts/test-vectors/keys/test-gateway-jwks.json}"
  [[ -f "$MCP_GATEWAY_JWKS_FILE" ]] || die "no $MCP_GATEWAY_JWKS_FILE: set MCP_CONTRACTS to the mcp-contracts checkout or MCP_GATEWAY_JWKS_URI"
  export MCP_ALLOW_TEST_KEYS=true
fi

# GitLab is optional (user-oauth + user-secret). MCP_GITLAB_URL is where the broker reaches GitLab (the stack's
# mock: http://localhost:18741); MCP_GITLAB_AUTHORIZE_URL is the address the user's browser opens (defaults to
# <MCP_GITLAB_URL>/oauth/authorize). The client secret is read from OpenBao (secret/mcp/oauth-clients/gitlab);
# MCP_GITLAB_CLIENT_SECRET is a development fallback for a stack where it is not there.
if [[ -n "${MCP_GITLAB_URL:-}" ]]; then
  export BROKER_SYSTEMS_GITLAB_BASEURL="$MCP_GITLAB_URL"
  export BROKER_SYSTEMS_GITLAB_ADAPTER=gitlab
  export BROKER_SYSTEMS_GITLAB_SUPPORTEDTYPES=user-oauth,user-secret
  export BROKER_SYSTEMS_GITLAB_DEFAULTTYPE=user-oauth
  export BROKER_SYSTEMS_GITLAB_OAUTHSCOPES="${MCP_GITLAB_SCOPES:-read_api}"
  export BROKER_SYSTEMS_GITLAB_OAUTH_CLIENTID="${MCP_GITLAB_CLIENT_ID:-mcp-broker}"
  if [[ -n "${MCP_GITLAB_CLIENT_SECRET:-}" ]]; then
    export BROKER_SYSTEMS_GITLAB_OAUTH_CLIENTSECRET="$MCP_GITLAB_CLIENT_SECRET"
  fi
  if [[ -n "${MCP_GITLAB_AUTHORIZE_URL:-}" ]]; then
    export BROKER_SYSTEMS_GITLAB_OAUTH_AUTHORIZEURL="$MCP_GITLAB_AUTHORIZE_URL"
  fi
fi

"$java_bin" -jar "$jar" &
broker_pid=$!
trap 'kill "$broker_pid" 2>/dev/null || true; wait "$broker_pid" 2>/dev/null || true' INT TERM
wait "$broker_pid" || status=$?
cleanup
exit "${status:-0}"
