#!/usr/bin/env bash
# Runs the broker on the host (https://localhost:18100) against mcp-platform-dev started with `make up`.
# Secrets are read from the environment's .secrets/dev.env at start, never copied into this repository.
#
# Without a running gateway the internal JWT keys come from the published TEST JWKS of mcp-contracts and
# test kids are allowed, so resolve can be called with tokens signed by the test keys. Dev only.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
dev="${MCP_PLATFORM_DEV:-$here/../mcp-platform-dev}"
contracts="${MCP_CONTRACTS:-$here/../mcp-contracts}"
jar="$here/target/mcp-credential-broker.jar"

[[ -f "$dev/.secrets/dev.env" ]] || { echo "no $dev/.secrets/dev.env: run make up in mcp-platform-dev" >&2; exit 1; }
[[ -f "$jar" ]] || { echo "no $jar: run ./mvnw -B package first" >&2; exit 1; }

set -a
# shellcheck disable=SC1091
. "$dev/.secrets/dev.env"
set +a

export MCP_BROKER_PORT="${MCP_BROKER_PORT:-18100}"
export MCP_TLS_KEYSTORE="$dev/certs/mcp-credential-broker/keystore.p12"
export MCP_TLS_TRUSTSTORE="$dev/certs/ca/truststore.p12"
export MCP_TLS_STORE_PASSWORD="$TLS_STORE_PASSWORD"
export MCP_DB_URL=jdbc:postgresql://localhost:15432/broker MCP_DB_USER=broker MCP_DB_PASSWORD="$BROKER_DB_PASSWORD"
export MCP_REDIS_HOST=localhost MCP_REDIS_PORT=16379 MCP_REDIS_USER=broker MCP_REDIS_PASSWORD="$REDIS_BROKER_PASSWORD"
export MCP_BAO_ADDR=http://localhost:18200 MCP_BAO_ROLE_ID="$BAO_BROKER_ROLE_ID" MCP_BAO_SECRET_ID="$BAO_BROKER_SECRET_ID"
export MCP_OIDC_ISSUER=http://localhost:18080/realms/corp
export MCP_OIDC_JWKS_URI=http://localhost:18080/realms/corp/protocol/openid-connect/certs
export MCP_JIRA_URL=http://localhost:18081
export MCP_PORTAL_URL="${MCP_PORTAL_URL:-http://localhost:18090}"
# OpenBao, Keycloak and the Jira mock of the dev stack speak plain HTTP.
export MCP_ALLOW_PLAIN_HTTP=true
if [[ -z "${MCP_GATEWAY_JWKS_URI:-}" ]]; then
  export MCP_GATEWAY_JWKS_FILE="${MCP_GATEWAY_JWKS_FILE:-$contracts/test-vectors/keys/test-gateway-jwks.json}"
  export MCP_ALLOW_TEST_KEYS=true
fi

exec "${JAVA_HOME:+$JAVA_HOME/bin/}java" -jar "$jar"
