# Changelog

The broker ships as a container image (`ghcr.io/aiwcorpo/mcp-credential-broker`); the version in `pom.xml` follows SemVer. Local and
integration builds tag the image `m6-<short sha>`.

## 1.0.0

First public release. Built on `mcp-contracts` 6.3.2.

- Holds users' credentials for the target systems, one per user and system, and hands them to the gateway at tool call time
  (`resolve`). Four credential types: a user secret (a single token, or a login and password sent as `Basic`), an OAuth grant
  connected through the portal, a token obtained by exchange at the identity provider, and a service-account key. The secret store
  is OpenBao: values are encrypted with Transit and stored in KV v2, one version at a time.
- OAuth connect flow with PKCE and one-time `state` (GitLab), refresh with a lock shared by all instances, and a sweep that renews
  tokens before they expire. A rotated refresh token that cannot be stored is revoked at the provider.
- A connection whose secret is gone from the secret store goes to state `error` and emits `connection_change` with reason
  `secret_missing` once; connecting again restores it. A brake limits how many rows are marked in a window.
- TOTP authenticator for confirming destructive actions: RFC 6238, a step is accepted once, five wrong codes in 15 minutes lock
  the user for 15 minutes, 20 in 24 hours disable the authenticator. All counters change under the row lock of the user, so the
  limits hold across instances. Codes can be burned by the gateway when a pending operation is cancelled.
- One verification of a user at a time per instance. A parallel request of the same user on the same instance is answered
  `503 upstream_unavailable` with `Retry-After: 1` before it takes a database connection, and does not count as an attempt, so a
  burst of guesses cannot starve other users of connections.
- Offboarding purge and cleanup of unused connections, both audited per item.
- Several instances on one PostgreSQL, Redis and OpenBao: migrations run once, enrollment confirmations are exclusive per user,
  nothing a verdict depends on is kept in the memory of an instance.
- Rejections of the gateway token are audited as event `authentication`, outcome `denied`, without `server`, `sub`, `tool` and
  `decision`; tokens with `mcp_risk` or `mcp_action` are `invalid_claims`. Infrastructure failures while checking the token are
  audited with reason `jwks_unavailable` or `replay_store_unavailable`. The response stays `503 upstream_unavailable`.
- Fail closed: an unreachable OpenBao, PostgreSQL, Redis, JWKS or identity provider is `503`, never a guess. The contract has no 500.
- Licensed under Apache-2.0, with SBOM profile `release` and a release workflow for ghcr.io. The `mcp-contracts` artifacts come
  from Maven Central.
