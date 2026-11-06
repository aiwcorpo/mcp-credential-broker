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
make ci                                              # ci/run.sh verify: text checks, mvnw clean verify, zero-test guard
```

`MultiInstanceIntegrationTest` starts extra broker JVMs on ports 18712-18717, so keep them free.

`ci/run.sh` has the steps `verify`, `unit` (tests that start no container), `hygiene` and `image` (image
`mcp-credential-broker:<MCP_IMAGE_STAGE>-<sha>`, built from a clean tree). The `mcp-contracts` artifacts come from Maven Central, so
no registry login is needed. The GitLab, Jenkins and GitHub files only call this script; a change request gets `unit` without the Docker
socket and without a token, the full run is for the main branch. The release workflow (`release.yml`) has three jobs: build
(read-only), publish (`packages: write`, only `docker load` and `docker push`) and release (`contents: write`, only `gh release create`).

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
| `DELETE /v1/admin/systems/{system}` | removes the system, the connections to it with their stored values, and the client secret |
| `GET /v1/systems` | what readers (gateway, portal) see: types, default type, OAuth scopes |

The caller is the portal BFF (client certificate `mcp-portal-bff`) with the token of a user whose `groups` claim has
`mcp-platform-admin`; the user token goes through the same checks as for every portal call. Anything else is `403`. A fresh MFA
is the BFF's business, the broker does not see it.

The adapter is chosen per system: `atlassian-dc` (Jira or Confluence Data Center, `whoami` for user secrets), `gitlab` (user
secrets and OAuth), `opensearch` (token exchange at the IdP) and `generic-rest` (a service-account key). The adapter has to fit
the credential types, as it did at start-up in 1.x: `user-oauth` needs an OAuth capable adapter and an `oauth` client,
`token-exchange` and `service-account` cannot be combined with other types, and so on; a mismatch is `422 system_rejected`.

Secrets: the `clientSecret` of the OAuth client is written to OpenBao at `secret/data/mcp/oauth-clients/<system>` (field
`client_secret`; mount and prefix are `broker.openbao.kv-mount` and `broker.openbao.oauth-clients-prefix`) and removed with
every version when the system is deleted. It is not stored in the table, never returned and never logged. The AppRole policy
needs `create`, `read`, `update`, `delete` on `secret/data/mcp/oauth-clients/*` and `read`, `delete` on
`secret/metadata/mcp/oauth-clients/*`. A replace keeps the secret only while `baseUrl`, `oauth.authorizeUrl`, `oauth.tokenUrl`
and `oauth.clientId` are unchanged; otherwise it asks for the secret again (`client_secret_required`), so a changed address never
receives the old one. A service-account key stays where the operator put it (`mcp/service-accounts/<system>`, read only).

Propagation: the table is the source of truth and every instance reads it every few seconds; the instance that handled a write
reloads at once. Redis pub/sub was not used for this because a lost message would leave an instance on an old list for good.

Deleting a system removes every user's connection to it (OAuth grants are revoked at the provider on a best effort basis),
publishes `credential.invalidated` for each, and writes `connection_change` (`system_deleted`) per connection and one
`admin_change`. After that `resolve` answers `422 system_not_configured`. The call is idempotent; repeat it after a failure.

Moving from 1.x: keep the old `broker.systems.*` settings for the first start of 2.0.0, which imports them into an empty table
once, then remove them. Details in the CHANGELOG.

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
