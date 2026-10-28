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
# A broker with newer migrations than the stack's own broker image must not share its database:
# set MCP_DB_URL, MCP_DB_USER and MCP_DB_PASSWORD to use another one.
export MCP_DB_URL="${MCP_DB_URL:-jdbc:postgresql://localhost:15432/broker}" MCP_DB_USER="${MCP_DB_USER:-broker}"
export MCP_DB_PASSWORD="${MCP_DB_PASSWORD:-$BROKER_DB_PASSWORD}"
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

# GitLab is optional (user-oauth + user-secret). MCP_GITLAB_URL is where the broker reaches GitLab;
# MCP_GITLAB_AUTHORIZE_URL is the address the user's browser opens (defaults to <MCP_GITLAB_URL>/oauth/authorize).
if [[ -n "${MCP_GITLAB_URL:-}" ]]; then
  : "${MCP_GITLAB_CLIENT_ID:?set MCP_GITLAB_CLIENT_ID}" "${MCP_GITLAB_CLIENT_SECRET:?set MCP_GITLAB_CLIENT_SECRET}"
  export BROKER_SYSTEMS_GITLAB_BASEURL="$MCP_GITLAB_URL"
  export BROKER_SYSTEMS_GITLAB_ADAPTER=gitlab
  export BROKER_SYSTEMS_GITLAB_SUPPORTEDTYPES=user-oauth,user-secret
  export BROKER_SYSTEMS_GITLAB_DEFAULTTYPE=user-oauth
  export BROKER_SYSTEMS_GITLAB_OAUTHSCOPES="${MCP_GITLAB_SCOPES:-read_api}"
  export BROKER_SYSTEMS_GITLAB_OAUTH_CLIENTID="$MCP_GITLAB_CLIENT_ID"
  export BROKER_SYSTEMS_GITLAB_OAUTH_CLIENTSECRET="$MCP_GITLAB_CLIENT_SECRET"
  if [[ -n "${MCP_GITLAB_AUTHORIZE_URL:-}" ]]; then
    export BROKER_SYSTEMS_GITLAB_OAUTH_AUTHORIZEURL="$MCP_GITLAB_AUTHORIZE_URL"
  fi
fi

exec "${JAVA_HOME:+$JAVA_HOME/bin/}java" -jar "$jar"
