# mcp-credential-broker

The place on the aiwcorpo MCP platform that holds each user's credential for each target system. The gateway asks it for the credential when a tool is called, the portal stores it for the signed-in user, and the broker also runs the TOTP authenticator that confirms destructive actions.

## Quick start

The broker is normally installed with the rest of the platform, through the Compose bundle in `mcp-platform`:

```bash
cd mcp-platform
cp platform.env .env        # set MCP_DOMAIN
docker compose up -d
```

Steps: [mcp-platform/README.md](https://github.com/aiwcorpo/mcp-platform#readme).

To run the broker alone (with its own PostgreSQL and Redis, against an OpenBao, an identity provider and a gateway you already have):

```bash
cd deploy
# put certs/keystore.p12 and certs/truststore.p12 in place, fill in the empty values in broker.env
docker compose up -d
docker compose logs init
```

OpenBao must be prepared first. Full steps: [deploy/README.md](deploy/README.md).

## Systems

Target systems are not configuration. An administrator adds them in the portal (Administration, Systems) and the broker picks the change up within 5 seconds, without a restart. The adapter decides how the broker talks to a system:

| Adapter | Credential types | What `whoami` calls |
| --- | --- | --- |
| `atlassian-dc` (`product`: `jira` or `confluence`) | `user-secret` | Jira `GET /rest/api/2/myself`, Confluence `GET /rest/api/user/current` |
| `gitlab` | `user-secret`, `user-oauth` | `GET /api/v4/user` |
| `opensearch` | `token-exchange` | nothing; the broker exchanges the user's token at the identity provider (`exchangeAudience` is required and must match `broker.token-exchange.allowed-audiences`) |
| `generic-rest` | `service-account`, or `user-secret` | `GET <baseUrl><path>` from the system's `whoami` setting, when one is set |

`whoami` checks a secret when the user stores it: a 2xx answer stores it, 401 or 403 rejects it (`secret_invalid`), anything else is `upstream_unavailable`. Addresses of a system are `https`. A change that moves a system to another address or OAuth client makes every connection to it `needs_reconnect`. Rules, API and storage details for developers: [CONTRIBUTING.md](CONTRIBUTING.md).

## Port

| Port | What |
| --- | --- |
| 8443 | HTTPS with a client certificate from the internal CA: the gateway (`mcp-gateway`), the portal (`mcp-portal-bff`) and the offboarding job (`mcp-offboarding`) |

## Configuration

Required, in `deploy/broker.env`. The Compose files set the database, Redis and store paths and generate passwords.

| Variable | Description |
| --- | --- |
| `MCP_PORTAL_URL` | public address of the portal |
| `MCP_OIDC_ISSUER`, `MCP_OIDC_JWKS_URI` | issuer and key set of the identity provider |
| `MCP_BAO_ADDR` | address of OpenBao |
| `MCP_BAO_ROLE_ID`, `MCP_BAO_SECRET_ID` | AppRole login to OpenBao |
| `MCP_GATEWAY_JWKS_URI` | key set of the gateway: `https://<gateway>:8443/.well-known/jwks.json` |
| `MCP_GATEWAY_TLS_NAME` | name in the gateway certificate (default in the file: `mcp-gateway.internal`) |
| `MCP_TLS_STORE_PASSWORD` | password of the stores in `certs/` |

The broker has two trust stores. `MCP_TLS_TRUSTSTORE` decides which client certificates its listener accepts, so keep only the internal CA in it. `MCP_TLS_OUTBOUND_TRUSTSTORE` (optional, same password) is what the broker trusts for the connections it opens: the identity provider, OpenBao, the gateway and the target systems. Without it the broker uses `MCP_TLS_TRUSTSTORE` for both. Put a company or public CA of a target system in the outbound store, so that it cannot issue callers of the broker.

Other settings are in `src/main/resources/application.yml`.

## Build

```bash
export JAVA_HOME=<path to JDK 25>
./mvnw -B verify
```

The jar is `target/mcp-credential-broker.jar`; `docker build -t mcp-credential-broker:dev .` builds the image. The tests start PostgreSQL, Redis and OpenBao with Testcontainers, so they need Docker. Working on the code: [CONTRIBUTING.md](CONTRIBUTING.md).

## More

- [deploy/README.md](deploy/README.md): installation, OpenBao setup, upgrade
- [CHANGELOG.md](CHANGELOG.md), [SECURITY.md](SECURITY.md)

Apache License 2.0.
