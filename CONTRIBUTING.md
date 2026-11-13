# Contributing

Changes go through a pull request.

- The API and the audit events follow `mcp-contracts` (`openapi/credential-broker.v1.yaml`, `schemas/audit-event.schema.json`).
  A change of an operation, a status code or a reason is made there first (`CONTRACT_CHANGES.md`); here you bump
  `mcp-contracts.version` and follow it. A contract test keeps the operation table (`Operation`) equal to the OpenAPI file.
- Do not put secret values in logs, audit events or error bodies; the tests check all of them.
- Commits: English subject up to 72 characters in the imperative mood, a body that describes the change.
- Never commit key material, `.env` files or the output of a build.

## Setup

JDK 25 and Docker (Testcontainers starts PostgreSQL 18, Redis and OpenBao). On Windows use WSL2. The `mcp-contracts` artifacts come
from Maven Central, so no registry login is needed.

```bash
./mvnw -B verify                                     # unit, contract and integration tests, jar
docker build -t mcp-credential-broker:dev .
```

`-Dtest='!*IntegrationTest'` runs only the tests that need no containers. `MultiInstanceIntegrationTest` starts extra broker JVMs on
ports 18712-18717, so keep them free.

CI runs `./mvnw -B verify`: a change request with `-Dtest='!*IntegrationTest'` (no containers, no Docker socket, no token), the main
branch in full. The release workflow (`release.yml`) has three jobs: build (read-only), publish (`packages: write`, only `docker load`
and `docker push`) and release (`contents: write`, only `gh release create`).

## Running locally

The run configuration `McpCredentialBroker (dev stack)` (`.run/`) starts the broker on `https://localhost:18710` against the dev
stack. Start the stack first (`make up` in `mcp-platform-dev`, next to this checkout; the configuration reads its `.secrets/dev.env`
and certificates, and the test JWKS of the gateway from `mcp-contracts`). The broker needs its own PostgreSQL, because its migrations
must not run against the database of the stack:

```bash
docker run -d --rm --name mcp-broker-host-pg -e POSTGRES_DB=broker -e POSTGRES_USER=broker -e POSTGRES_PASSWORD=broker \
  -p 127.0.0.1:18711:5432 postgres:18.6-alpine
```

Stop it with `docker stop mcp-broker-host-pg`. The Jira system is created from `BROKER_SYSTEMS_JIRA_*` in an empty table; later
changes go through `PUT /v1/admin/systems/jira`.

Relaxations for a dev stack (published `test-*` signing keys, `dev-` keys, plain http) need `MCP_ALLOW_TEST_KEYS=true` and the Spring
profile `devstack`, and are logged at start.

## Systems

Systems are rows of `target_system`, changed through the admin API and visible to every instance within
`broker.system-sync.interval` (5 s). Nothing in the code or in `application.yml` lists a system. Several instances can share one
PostgreSQL, one Redis and one OpenBao; counters and locks are rows and transactions, one-time state is in Redis.

| Operation | Meaning |
| --- | --- |
| `GET /v1/admin/systems`, `GET /v1/admin/systems/{system}` | configuration without secrets; the single read has an `ETag` |
| `PUT /v1/admin/systems/{system}` | create (`If-None-Match: *`) or replace (`If-Match: <ETag>`); `412` when stale, `428` without either |
| `DELETE /v1/admin/systems/{system}` | `If-Match` required; removes the system, the connections to it with their stored values, and the client secret version |
| `GET`, `PUT`, `DELETE /v1/admin/systems/{system}/service-account-key` | the key of a `service-account` system, write-only (below) |
| `GET /v1/systems` | what the gateway and the portal see: types, default type, OAuth scopes |

- Malformed input (an `If-Match` value, a path id that does not match `SystemId`) is `400`. A well-formed id with no system is `404`
  (`204` for a `DELETE`).
- Callers: the portal BFF (certificate `mcp-portal-bff`) with the token of a user in `mcp-platform-admin`. A `PUT` or `DELETE` also
  needs a fresh MFA in the token (`auth_time` within 300 s and `acr` in `broker.bff-token.mfa-acr-values`, or `amr` with one of
  `broker.bff-token.mfa-amr-values`: `mfa`, `otp`, `hwk`, `totp`); otherwise `401 step_up_required`.
- The adapter must fit the credential types (`SystemRules`): `user-oauth` needs an OAuth capable adapter (`gitlab`) and
  `oauth.authorizeUrl` and `oauth.tokenUrl`; `token-exchange` and `service-account` cannot be combined with other types; a mismatch
  is `422 system_rejected`. A `token-exchange` system takes no `tokenUrl`: the broker uses the token endpoint of its identity
  provider (`broker.bff-token.token-url`).
- A `generic-rest` system may take user secrets instead of a service-account key (never both, never OAuth). Without a `whoami` the
  secret is stored unverified (`verified` false, audit reason `secret_stored_unverified`).
- Token exchange sends the result to `baseUrl`, so the audience is restricted by `broker.token-exchange.allowed-audiences` (exact
  values or patterns with `*`). Empty by default: no token-exchange system can be created (`422 audience_not_allowed`).
- `baseUrl`, `oauth.authorizeUrl`, `oauth.tokenUrl` and `revokeUrl` are `https`; plain `http` only with `broker.allow-plain-http`
  (dev stack).
- A change of `baseUrl`, `oauth.authorizeUrl`, `oauth.tokenUrl`, `oauth.clientId` or `revokeUrl` makes every connection of the system
  lose its grant and stored value and get `needs_reconnect`; `credential.invalidated` is published per connection. Nothing is sent
  to any provider. Every grant records the client revision it was issued under; a refresh, revoke or resolve under another revision
  is refused. Other changes (scopes, timeout, default type, the secret) leave connections alone.
- Deleting a system removes every connection to it with its stored value and publishes `credential.invalidated` for each. After that
  `resolve` answers `422 system_not_configured`. The call is idempotent. The system is withdrawn first (`withdrawn_at`), together
  with marking its connections `needs_reconnect`, so a delete that fails halfway leaves it out of service and hidden from the
  admin reads; repeating the `DELETE` (its `If-Match` is not compared then) finishes it, and the id cannot be created again before.
- Client secrets live in OpenBao KV v2 at `secret/data/mcp/system-clients/<system>`, field `client_secret`
  (`broker.openbao.system-clients-prefix`). A write is a check-and-set to a new version, written before the row; the row stores that
  version and a new etag in one conditional update. A change that loses the race destroys the version it wrote. A replace keeps the
  secret only while the five addresses and the client stay as they are, otherwise `client_secret_required`. The AppRole policy for all of this is in
  `deploy/README.md`.
- The service-account key (CC-251) is at `secret/data/mcp/service-accounts/<system>` (`broker.openbao.service-accounts-prefix`):
  `value`, or `username` and `password` for a `Basic` system, optionally `expires_at`, plus `updated_by` which the reader of the
  key ignores. `PUT` replaces the whole entry with a new KV version (last write wins, no `If-Match`), needs `service-account` in
  `supportedTypes` and a fresh MFA, and answers the status only: no operation returns the key. `GET` shows `set`, `kvVersion`,
  `expiresAt`, `expired`, `updatedAt` and `updatedBy`. `DELETE` removes the entry with all its versions (metadata delete) and
  accepts any configured system, so a leftover key can go; for an id with no system it removes an orphan left by a failed removal
  (`204`) and is `404` when nothing is there. Creating a system removes whatever is stored under its id first and answers `503`
  when that fails. Deleting a system removes its key too when one is there, and
  `SystemAdminView.serviceAccountKey` says `set`, `missing` or `unknown`; a secret store that does not answer gives `unknown`
  there but `503` for the key operations. Audit reasons `service_account_key_set` and `service_account_key_deleted` carry
  `kvVersion` (and `expiresAt` on a set), never the key. The policy needs `create`, `read` and `update` on the data path, `delete` on the metadata path and `update` on the destroy path;
  without it `PUT` and `DELETE` of the key, and the creation and removal of any system, answer `503`, and `init` warns about the
  missing rights. A write is checked against the row again afterwards (deleted, re-created or changed system: the entry is removed
  and the call is `404` or `422`), the previous version is destroyed, creating a system, or adding `service-account` to one, removes what is stored under its id first, and an
  update that drops `service-account` removes the key. A key left behind by a failed removal is not in `SystemAdminView` for a
  system without `service-account` (the field is absent there); `GET` of the key shows it.
- Moving from 1.x: keep the old `broker.systems.*` settings for the first start of 2.0.0. It imports them into an empty table once
  and copies the client secrets from `mcp/oauth-clients/<system>`. Then remove them. Details in the CHANGELOG.

New credential types go into `CredentialType` and `SystemRules`, new operations into `Operation`.

## Invariants to keep

- Fail closed: an unreachable OpenBao, PostgreSQL, Redis, JWKS or identity provider is `503 upstream_unavailable`. The contract has
  no 500.
- The caller is identified by the certificate CN and the token together; the user (`sub`) always comes from the token. Internal
  tokens are ES256, one-time (`jti` in Redis) and checked against the contract vectors.
- Values are encrypted with Transit before they are written to KV; the record holds its owner. Secrets are returned only by
  `resolve` and never reach logs or audit events.
- TOTP codes: RFC 6238, a step is accepted once. Five wrong codes in 15 minutes lock the user for 15 minutes, 20 in 24 hours disable
  the authenticator. Counters change in one transaction under the row lock of the user. The limits are constants of the contract.
- One verification of a user at a time per instance; a parallel one is refused with `503 upstream_unavailable` and does not count as
  an attempt. A code burned by the gateway (`invalidate-codes`) does not count towards the lock.
- Rate limits are per user, kept in Redis; exceeding one is `429` with `Retry-After`.
- Offboarding (`purge`, called by `mcp-offboarding` only) removes everything held about a user and revokes the grants.
- Keys published for tests are refused outside the dev profile.

## Source layout

Packages under `pl.aiwcorpo.mcp.broker`: `auth` (mTLS CN, internal JWT, BFF token, operation table), `api` (controllers, error
mapping), `credential` (resolve, PUT secret, OAuth, offboarding), `oauth` (flows, refresh lock, rate limits), `authenticator` (TOTP,
enrollment, seed store, metadata), `secret` (OpenBao client, secret store), `system` (stored systems, registry, admin service and the
adapters), `audit`, `event` and `config`.

## License

Contributions are licensed under Apache-2.0 (see `LICENSE`).
