# AGENTS.md

mcp-credential-broker holds each user's credential for each target system of [MCP Platform](https://github.com/aiwcorpo/mcp-platform)
(values in OpenBao, encrypted with Transit) and runs the TOTP authenticator for destructive actions. Callers, over mTLS on port
8443: the gateway (CN `mcp-gateway`), the portal BFF (`mcp-portal-bff`) and the offboarding job (`mcp-offboarding`). It calls
OpenBao, PostgreSQL, Redis, the identity provider, the gateway JWKS and the target systems. Its API and audit events are
governed by `mcp-contracts`: `openapi/credential-broker.v1.yaml` (C4) and `schemas/audit-event.schema.json`.
Human docs: [README.md](README.md), [CONTRIBUTING.md](CONTRIBUTING.md), [deploy/README.md](deploy/README.md).

## Commands

Maven needs JDK 25. If `java -version` shows an older JDK, point `JAVA_HOME` at a JDK 25 first (macOS with Homebrew:
`export JAVA_HOME=$(brew --prefix openjdk@25)`).

```bash
./mvnw -B verify '-Dtest=!*IntegrationTest'   # no containers; what CI runs on a pull request
./mvnw -B verify                              # full run: Testcontainers starts PostgreSQL 18, Redis, OpenBao; needs Docker
./mvnw -B test -Dtest=CredentialServiceTest   # one test class
docker build -t mcp-credential-broker:dev .
```

The full verify (about 620 tests) takes about 5 minutes, the container-free run about 1. CI runs the full one on main, so
run it before a PR even though the PR job skips it.
`MultiInstanceIntegrationTest` starts extra broker JVMs on ports 18712-18717; keep them free. There is no lint or
formatter step.

## Layout

- `src/test/java/.../broker/it/`: integration tests (`*IntegrationTest`, Testcontainers). Everything else under
  `src/test` runs without Docker.
- `src/main/resources/db/migration/`: Flyway `V1`..`V11`. Never edit an applied migration; add the next number.
- `deploy/`: standalone Compose install of the broker. `deploy/certs/` is git-ignored; nothing goes in there in a commit.
- `.run/`: IntelliJ run configuration against the dev stack of `mcp-platform-dev`.

## Rules

- Contract first. A change of an operation, status code, reason or audit field starts in `mcp-contracts`
  (`CONTRACT_CHANGES.md` entry approved by a person). Here you only bump `mcp-contracts.version` in `pom.xml` and follow it.
  A contract test keeps the `Operation` table equal to the OpenAPI file.
- New credential types go into `CredentialType` and `SystemRules`, new operations into `Operation`. Target systems are rows
  of `target_system` managed through the admin API; never add a system to code or `application.yml`.
- Fail closed: an unreachable OpenBao, PostgreSQL, Redis, JWKS or identity provider is `503 upstream_unavailable`. The
  contract has no 500; do not introduce one.
- Never log, audit or put in an error body: stored secret values, OAuth access and refresh tokens, client secrets, TOTP
  seeds and codes, internal JWTs, OpenBao tokens, AppRole `secret_id`. Secrets leave the broker only through `resolve`.
  Tests assert this; extend them when you add a new field that carries a secret.
- The user (`sub`) always comes from the token, the caller from the certificate CN and the token together.
- `MCP_TLS_TRUSTSTORE` decides which client certificates port 8443 accepts and must hold only the internal CA. Company or
  public CAs for target systems belong in `MCP_TLS_OUTBOUND_TRUSTSTORE`. Do not merge the two or add a CA to the inbound one.
- Keys published for tests (`test-*`, `dev-`) and plain http are allowed only with `MCP_ALLOW_TEST_KEYS=true` and the
  `devstack` profile. Keep them refused everywhere else.
- TOTP lock limits (5 in 15 min, 20 in 24 h) are constants of the contract; do not make them configurable.
- Base images are pinned by digest (`Dockerfile`, `deploy/compose.yaml`). Change tag and digest together.
- Test methods are sentences in camelCase that state the behaviour, for example
  `anUpsertWhoseOutcomeCannotBeReadDeletesNothing`. Tests use dummy data only.
- `CHANGELOG.md` has no "Unreleased" section. Ask the person which version heading a user-visible change goes under.

## Boundaries

Do not do any of this without a person's explicit yes: change the version in `pom.xml` or `deploy/compose.yaml`, tag,
release, push to main, publish images (they go to ghcr.io only, via `release.yml`), run the `.run/` configuration or
anything else against a running stack or real OpenBao, Keycloak or target system.
Never commit secrets, tokens, keystores, generated keys, `.env` or `broker.env` with values, `.secrets/` content, internal
host names or IP addresses.

## Pull requests

One change per PR. Commit subject in English, imperative, up to 72 characters; the body says what changed and why, not the
process. Tests go in the same commit as the code. `./mvnw -B verify` must pass. Update README, `deploy/README.md` or
CONTRIBUTING when configuration or behaviour visible to operators changes. See [CONTRIBUTING.md](CONTRIBUTING.md).
