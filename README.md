# mcp-credential-broker

The only place on the MCP platform that holds users' credentials for the target systems, one per user and system. The gateway
asks it for the credential when a tool is called (`resolve`); the portal BFF stores it on behalf of the signed-in user. The broker
also runs the TOTP authenticator that confirms destructive actions, and the OAuth connect flow for systems that support it
(GitLab).

It is a deployable component (container image `mcp-credential-broker`), not a library. The intended readers are platform operators.
Installation and day-to-day operation of the whole platform are described in
[mcp-docs](https://github.com/aiwcorpo/mcp-docs), starting from `docs/operator/index.md`.

Contracts: `mcp-contracts` 7.0.0 (`openapi/credential-broker.v1.yaml`, audit events, test vectors). What works, what is missing and
the known deviations: [STATUS.md](STATUS.md) (in Polish). License: Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)).
Changes: [CHANGELOG.md](CHANGELOG.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Reporting vulnerabilities: [SECURITY.md](SECURITY.md).

## What it needs

PostgreSQL (the target systems, connection metadata and authenticator counters; Flyway creates the schema at start), Redis with a `broker` account
(one-time OAuth flows, refresh locks, rate limits, `jti` of internal tokens, `credential.invalidated` events), OpenBao (AppRole
login, KV v2 for values, Transit for the authenticator seeds), the identity provider's JWKS for BFF tokens, and the gateway's
JWKS for the internal JWT. Everything is reached over TLS; callers need a client certificate from the internal CA. The Compose install in `mcp-docs`
(`examples/compose`) gives a single-machine stack for trying it out; its settings are not for production.

The broker listens on one HTTPS port (`8443` in the container). The API, the allowed certificate CN per operation and the error
bodies are defined by the contract; the table in `docs/reference/api-operations.md` of mcp-docs lists them.

## Build and test

JDK 25 and Docker are required (Testcontainers starts PostgreSQL 18, Redis and OpenBao). On Windows use WSL2.

```bash
./mvnw -B verify                                     # unit, contract and integration tests, jar
docker build -t mcp-credential-broker:dev .
```

`MultiInstanceIntegrationTest` starts extra broker JVMs on ports 18712-18717, so keep them free. The `mcp-contracts` artifacts come
from Maven Central, so no registry login is needed. The GitLab, Jenkins and GitHub files call `./mvnw -B verify`; a change request
runs it with `-Dtest='!*IntegrationTest'` (no containers, no Docker socket, no token), the full run is for the main branch. The release
workflow (`release.yml`) has three jobs: build (read-only), publish (`packages: write`, only `docker load` and `docker push`) and
release (`contents: write`, only `gh release create`).

### Run locally

The run configuration `McpCredentialBroker (dev stack)` (`.run/`, IntelliJ picks it up) starts the broker on `https://localhost:18710`
against the dev stack: start that first (`make up` in `mcp-platform-dev`, next to this checkout; the configuration reads its
`.secrets/dev.env` and certificates, and the test JWKS of the gateway from `mcp-contracts`, also next to this checkout). The broker
gets its own PostgreSQL, because its migrations must not run against the stack's database:

```bash
docker run -d --rm --name mcp-broker-host-pg -e POSTGRES_DB=broker -e POSTGRES_USER=broker -e POSTGRES_PASSWORD=broker \
  -p 127.0.0.1:18711:5432 postgres:18.6-alpine
```

Stop it with `docker stop mcp-broker-host-pg`. Edit the variables of the configuration to use other addresses or another database.
The Jira system is created from `BROKER_SYSTEMS_JIRA_*` in an empty table; later changes go through `PUT /v1/admin/systems/jira`.

## Configuration

All settings are environment variables read from `src/main/resources/application.yml`. The generated table of variables, defaults
and which ones are mandatory is in mcp-docs: `docs/reference/env-broker.md`. Do not copy it here. Target systems are not configuration: see
"Systems" below. `broker.system-sync.interval` (5 s) is how often an instance reads them again.

The shortest set needed to start: `MCP_DB_URL`, `MCP_DB_USER`, `MCP_DB_PASSWORD`; `MCP_REDIS_HOST`, `MCP_REDIS_USER`,
`MCP_REDIS_PASSWORD`; `MCP_BAO_ADDR`, `MCP_BAO_ROLE_ID`, `MCP_BAO_SECRET_ID`; `MCP_TLS_KEYSTORE`, `MCP_TLS_TRUSTSTORE`,
`MCP_TLS_STORE_PASSWORD`; `MCP_OIDC_ISSUER`, `MCP_OIDC_JWKS_URI`; `MCP_GATEWAY_JWKS_URI` (or `MCP_GATEWAY_JWKS_FILE`) with
`MCP_GATEWAY_TLS_NAME`; `MCP_PORTAL_URL`.

Several instances can run on one PostgreSQL, one Redis and one OpenBao. Nothing a verdict depends on lives in the memory of an
instance: counters and locks are rows and transactions in PostgreSQL, one-time state is in Redis.

### Development profile

Relaxations meant only for a dev stack (published `test-*` signing keys, `dev-` keys, plain http) need `MCP_ALLOW_TEST_KEYS=true` and
the Spring profile `devstack`, and are logged at start. Details: `docs/operator/dev-profile.md` in mcp-docs.

## Systems

The systems the broker resolves credentials for are rows of `target_system`, changed through the admin API of C4 and visible
to every instance within `broker.system-sync.interval` (5 s by default), without a restart. Nothing in the code or in
`application.yml` lists a system.

| Operation | Meaning |
| --- | --- |
| `GET /v1/admin/systems`, `GET /v1/admin/systems/{system}` | configuration without secrets; the single read has an `ETag` |
| `PUT /v1/admin/systems/{system}` | create (`If-None-Match: *`) or replace (`If-Match: <ETag>`); `412` when stale, `428` without either |
| `DELETE /v1/admin/systems/{system}` | `If-Match` required; removes the system, the connections to it with their stored values, and the client secret version |
| `GET /v1/systems` | what readers (gateway, portal) see: types, default type, OAuth scopes |

Input that is not well formed (an `If-Match` or `If-None-Match` value, a path id that does not match `SystemId`) is `400`, never
`404`; a well-formed id with no system is `404` (`204` for a `DELETE`), a stale `If-Match` is `412`. A system can have a
`displayName` for the portal; the admin view shows the id when none is set.

Callers: the portal BFF (client certificate `mcp-portal-bff`) with the token of a user whose `groups` claim has
`mcp-platform-admin`. Anything else is `403`. A `PUT` or `DELETE` also needs proof of a fresh MFA in that token: `auth_time` no older than 300 seconds and
either `acr` in `broker.bff-token.mfa-acr-values` (empty by default) or `amr` containing one of
`broker.bff-token.mfa-amr-values` (`mfa`, `otp`, `hwk`, `totp` by default). A recent password login is not enough. Otherwise
`401 step_up_required`, audited; the broker checks the MFA itself, the BFF asking for it is not relied on.

The adapter is chosen per system: `atlassian-dc` (Jira or Confluence Data Center; `product` is `jira` or `confluence`, never
detected), `gitlab` (user secrets and OAuth), `opensearch` (token exchange at the IdP; `exchangeAudience` is required) and
`generic-rest` (a service-account key). The adapter has to fit the credential types, as it did at start-up in 1.x:
`user-oauth` needs an OAuth capable adapter and `oauth.authorizeUrl` and `oauth.tokenUrl`, `token-exchange` and
`service-account` cannot be combined with other types, and so on; a mismatch is `422 system_rejected`. A `token-exchange`
system takes no `tokenUrl`: the broker always uses the token endpoint of its identity provider
(`broker.bff-token.token-url`, `BROKER_BFFTOKEN_TOKENURL`; Keycloak's path under `MCP_OIDC_ISSUER` when not set).

A `generic-rest` system may take user secrets instead of a service-account key (never both, never OAuth). With a `whoami`
(`path` relative to `baseUrl`, `usernameField` a top-level field or a JSON pointer) the broker checks a secret with
`GET baseUrl+path` when it is stored: a 2xx with the field stores it with that backend user, 401 or 403 is `secret_invalid`,
anything else `upstream_unavailable`. Without one the secret is stored unverified (`verified` false, no backend user, audit reason
`secret_stored_unverified`). The gateway gets the stored secret from `resolve` as for any user-secret system.

Token exchange: the broker exchanges the caller's token for the `exchangeAudience` of the system and sends the result to its
`baseUrl`, so the audience is restricted by configuration: `broker.token-exchange.allowed-audiences` (exact values or patterns
with `*`, `BROKER_TOKENEXCHANGE_ALLOWEDAUDIENCES`). Empty by default, which means no token-exchange system can be created
(`422`, reason `audience_not_allowed`). A stored system whose audience is not allowed is refused at `resolve`, with a warning
when the systems are loaded.

Addresses: every URL an administrator gives (`baseUrl`, `oauth.authorizeUrl`, `oauth.tokenUrl`, `revokeUrl`) is `https`. Plain
`http` is accepted only when `broker.allow-plain-http` is set, which is for a development stack only.

When a change moves where the system points (`baseUrl`, `oauth.authorizeUrl`, `oauth.tokenUrl`, `oauth.clientId` or
`revokeUrl`), every connection of the system loses its grant and its stored value and gets the status `needs_reconnect`;
`credential.invalidated` is published per connection and `connections_invalidated` is audited. The connections are marked in the
same transaction that changes the row of the system; deleting their stored values follows, and every later write of the system
finishes it if it was interrupted (the write that was interrupted fails with 503). Nothing is sent to any
provider, neither to the old address nor to the new one. Other changes (scopes, timeout, default type, the secret itself) leave
the connections alone. Every grant records the client revision it was issued under; a refresh, a revoke or a resolve with a
different revision, or with none, is refused (the import gives the connections of 1.x their system's revision), so an instance that has not yet seen a change cannot use a grant with the new definition. A
pending OAuth flow of the old revision cannot be completed either. A connection whose credential type the system dropped is
`needs_reconnect` as well.

Client secrets (`oauth.clientSecret`, also the IdP client secret of a token-exchange system) are in OpenBao KV v2 at
`<kv-mount>/data/<system-clients-prefix>/<system>`, field `client_secret`, by default `secret/data/mcp/system-clients/<system>`
(`broker.openbao.system-clients-prefix`), a prefix of nothing else. A write is a check-and-set to a new version, written before
the row; the row stores that version and a new etag in one conditional update, and every reader asks for exactly that version.
A change that loses the race destroys the version it wrote, and a rotated or removed version is destroyed, so two concurrent
changes never leave the secret of one beside the configuration of the other. The secret is never in the table, a response or a
log. A replace keeps it only while the five addresses and the client stay as they are; otherwise it asks for it again
(`client_secret_required`). A service-account key stays where the operator put it (`mcp/service-accounts/<system>`, read only).

The AppRole policy of the broker needs these lines for the admin API (the lines for `mcp/connections`, the authenticators and
`mcp/service-accounts` are unchanged):

```
path "secret/data/mcp/system-clients/*"     { capabilities = ["create", "read", "update"] }
path "secret/metadata/mcp/system-clients/*" { capabilities = ["read"] }
path "secret/destroy/mcp/system-clients/*"  { capabilities = ["update"] }
path "secret/data/mcp/oauth-clients/*"      { capabilities = ["read"] }
```

The last line is the path 1.x read; it is used only by the import of the 1.x properties (below) and can be removed afterwards.

Propagation: the table is the source of truth and every instance reads it every few seconds; the instance that handled a write
reloads at once. Redis pub/sub was not used for this because a lost message would leave an instance on an old list for good.
`connection.system` has a foreign key to the table, so a stale instance cannot write a connection to a system that was deleted.

Deleting a system removes every user's connection to it with its stored value, publishes `credential.invalidated` for each, and
writes `connection_change` (`system_deleted`) per connection and `admin_change` (`system_deleted`, `connections_invalidated`).
Nothing is sent to the provider: a grant is not revoked with a definition other than the one it was issued under, and that one
may be gone. After that `resolve` answers `422 system_not_configured`. A delete of an id that has no system is `204` and removes
nothing. Creating a system whose id still has connections left behind purges them first, again without sending anything.
The call is idempotent; repeat it after a failure.

Moving from 1.x: keep the old `broker.systems.*` settings for the first start of 2.0.0. It imports them into an empty table
once, in one transaction under a database lock, copies the client secrets from `mcp/oauth-clients/<system>` to the new path
and writes a marker; on that first start the marker is written whatever the settings say. Then remove them. Details in the
CHANGELOG.

## Security

Invariants of this component. The platform-wide list is in `docs/security/invariants.md` of mcp-docs.

- Fail closed: an unreachable OpenBao, PostgreSQL, Redis, JWKS or identity provider is `503 upstream_unavailable`, never a guess.
  The contract has no 500.
- The caller is identified by the certificate CN and the token together, and the user (`sub`) always comes from the token, never
  from the path, query or body. Internal tokens are ES256, one-time (`jti` in Redis) and checked against the contract vectors.
- Values are encrypted with Transit before they are written to KV; the record holds its owner, and a ciphertext moved under another
  path gives `503`, not another user's secret. Secrets are returned only by `resolve` and never reach logs or audit events.
- TOTP codes: RFC 6238, a step is accepted once. Five wrong codes in 15 minutes lock the user for 15 minutes, 20 in 24 hours
  disable the authenticator until it is registered again. Counters, lock and registration change in one transaction under the row
  lock of the user, so the limits hold across instances. The limits are constants of the contract, not configuration.
- One verification of a user at a time per instance. A parallel request of the same user on the same instance is refused at once with
  `503 upstream_unavailable`, does not count as an attempt and says nothing about the code; this keeps a burst of
  guesses from holding the database connections other users need.
- A code burned by the gateway (`invalidate-codes`) is not a wrong guess and does not count towards the lock.
- Rate limits are per user and kept in Redis; exceeding one is `429` with `Retry-After`.
- Offboarding (`purge`, called by `mcp-offboarding` only) removes everything held about a user: values in every KV version, connection
  rows, OAuth flows in progress, the authenticator with its seeds, and revokes the grants at the provider.
- Keys published for tests are refused outside the dev profile.

## Source layout

Packages under `pl.aiwcorpo.mcp.broker`: `auth` (mTLS CN, internal JWT, BFF token, operation table), `api` (controllers, error
mapping), `credential` (resolve, PUT secret, OAuth, offboarding), `oauth` (flows, refresh lock, rate limits), `authenticator` (TOTP,
enrollment, seed store, metadata), `secret` (OpenBao client, secret store), `system` (the stored systems, their registry and admin
service, adapters for Atlassian DC, GitLab, OpenSearch and a generic REST system), `audit`, `event` and `config`.

New credential types go into `CredentialType` and `SystemRules`, new operations into `Operation`; a contract test keeps the table
equal to the OpenAPI file.
