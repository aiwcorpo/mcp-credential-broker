# Changelog

The broker ships as a container image (`ghcr.io/aiwcorpo/mcp-credential-broker`); the version in `pom.xml` follows SemVer. Local and
integration builds tag the image `m6-<short sha>`.

## 2.0.0

Built on `mcp-contracts` 7.0.0 (CC-229, CC-235, CC-237, CC-238). Breaking: the systems are no longer configuration.

- Systems live in PostgreSQL (table `target_system`, migrations `V7` and `V8`) and are managed through the admin API of C4:
  `GET /v1/admin/systems`, `GET`, `PUT` and `DELETE /v1/admin/systems/{system}`. Callers are the portal BFF (certificate
  CN `mcp-portal-bff`) with the token of a user in the group `mcp-platform-admin` (claim `groups`); anything else is `403`.
  A `PUT` or `DELETE` also needs proof of a fresh MFA in the token: `auth_time` not older than 300 s and an `acr` in
  `broker.bff-token.mfa-acr-values` or an `amr` with one of `broker.bff-token.mfa-amr-values` (default `mfa`, `otp`, `hwk`,
  `totp`), else `401 step_up_required`. A create sends
  `If-None-Match: *`, a replace and a delete send `If-Match` with the `ETag` of the last read (`412` when stale, `428` when
  missing). The response never carries a secret, only `clientSecretSet`.
- The request and view have `product` (`jira` or `confluence`, required for `atlassian-dc`, forbidden otherwise; the probing
  of Jira's and Confluence's paths is gone), `revokeUrl`, `timeout` (ISO 8601, at most 10 minutes), `exchangeAudience`
  (required for `token-exchange`, forbidden otherwise) and `userSecretScheme` (`Bearer` or `Basic`; anything else is `400`).
  `authorizeUrl` is only for `user-oauth`. A `token-exchange` system takes no `tokenUrl`: it is always the token endpoint of
  the broker's identity provider (`broker.bff-token.token-url`, default Keycloak's path under `MCP_OIDC_ISSUER`), and a body
  with one is `422 token_url_not_settable`.
- Every URL from an administrator is `https`; `http` only when `broker.allow-plain-http` is set (development).
- Per system the adapter is chosen: `atlassian-dc`, `gitlab`, `opensearch` or `generic-rest`. The checks of the 1.x start-up
  now answer `422 system_rejected` with a reason: `adapter_type_mismatch`, `credential_types_mixed`,
  `default_type_not_supported`, `oauth_required`, `secret_scheme_not_supported`, `product_required`,
  `exchange_audience_required`, `system_reserved`, `client_secret_required`, `token_url_not_settable`,
  `authorize_url_not_settable`, `revoke_url_not_settable`. Ids follow `SystemId` (`^[a-z][a-z0-9]{1,30}$`, without the reserved
  names `gateway`, `offboarding`, `portal`, `broker`, `prometheus`, `platform`, `admin`, `registry`, `adapter`, `internal`, `ci`).
- A change of `baseUrl`, `oauth.authorizeUrl`, `oauth.tokenUrl`, `oauth.clientId` or `revokeUrl` invalidates every connection of
  the system: grants and stored values are deleted, pending flows die, the connections get the new status `needs_reconnect`,
  `credential.invalidated` is published per connection and `connections_invalidated` is audited, and nothing is sent to any
  endpoint, old or new. A grant records the client revision it was issued under (the revision moves only on such a change, so a
  change of scopes does not break refresh); a refresh, a revoke or a resolve under another revision, or without one, is
  refused. Migration `V9` gives existing connections of systems that are rows the revision of their system, and the import of
  1.x does the same for the others. The connections are marked `needs_reconnect` in the same transaction that updates the
  system row; deleting their stored values follows and is finished by the next write of the system if it was interrupted. A DELETE never
  calls a provider either. Creating a system whose id has leftovers purges them first, without sending anything.
- Client secrets are written to OpenBao KV v2 first, as a new version with check-and-set, at
  `secret/data/mcp/system-clients/<system>` (`broker.openbao.system-clients-prefix`; it replaces the path `mcp/oauth-clients`
  of 1.x, which is read only by the import). The row stores the version together with its new etag in one conditional update,
  readers ask for exactly that version, and a version that no row points at is destroyed (a lost race, a rotation, a delete).
  A PUT without a secret keeps it only while the five addresses and the client are unchanged. **The AppRole policy needs
  `create`, `read`, `update` on `secret/data/mcp/system-clients/*`, `read` on `secret/metadata/mcp/system-clients/*`, `update`
  on `secret/destroy/mcp/system-clients/*`, and `read` on `secret/data/mcp/oauth-clients/*` for the import** (README lists
  the lines).
- Every instance polls the table (`broker.system-sync.interval`, 5 s by default) and swaps its list of systems, so a change
  made on any instance is visible on all of them within about that interval, without a restart; the instance that took the
  write reloads at once. Polling was chosen over Redis pub/sub because a lost message would leave an instance on an old list
  until the next restart, and the broker's Redis account may publish only `credential.invalidated`. A foreign key from
  `connection.system` to the table (not validated for rows of 1.x) makes a write of an instance that has not seen a delete
  fail.
- `DELETE` removes the connections of users to the system and their stored values (each removal publishes
  `credential.invalidated` and writes `connection_change` with reason `system_deleted`), then the row and the version of the
  client secret. A `DELETE` of an id that has no system is `204` and deletes nothing. It can be repeated after a failure.
- `GET /v1/systems` reads the stored systems. `resolve` for an id nobody configured answers `422 system_not_configured`.
  The audit field `server` is written only for an id that has a system, or that the call itself creates or removes.
- Every change writes an `admin_change` event with reason `system_created`, `system_updated`, `system_deleted` or
  `connections_invalidated` (`denied` with the reason of the refusal, such as `precondition_failed`, `not_admin` or
  `step_up_required`), the administrator as `sub` and the system as `server`. The audit field `policyRevision` and the claim
  `prv` of the internal JWT are integers (CC-237).
- **Removed:** the list of known systems in the code (`SystemRegistry.KNOWN_SYSTEMS`) and the `broker.systems` block of
  `application.yml`. `MCP_JIRA_URL` and the other per system variables are no longer required.

### Moving from 1.x

1. Back up PostgreSQL, and give the AppRole of the broker the policy lines above.
2. Keep the `BROKER_SYSTEMS_*` (or `broker.systems.*`) settings of 1.x for the first start of 2.0.0. On that start the broker
   takes a database lock and, in one transaction, stores those systems when the table is empty and writes a marker
   (`target_system_import`); the marker is written whatever the settings say, also when they are absent or the table already
   has systems, so deleting every system later does not bring them back. One `admin_change` event `system_imported` per system.
   Ids that are not valid system ids stop the start with an error naming them. An `atlassian-dc` system gets its product from
   its old id (`jira` or `confluence`); one with another id stops the start and has to be created through the API. The client
   secret is copied from `mcp/oauth-clients/<system>` to the new path (a dev only `oauth.client-secret` property is written
   there instead), `token-exchange` systems use the token endpoint of the broker's identity provider, and connections of 1.x
   are adopted under the revision of their system. Fields that the admin API now has (`timeout`, `revoke-url`,
   `user-secret-scheme`, the exchange audience) are imported; `deployment` is imported and kept when the system is replaced.
3. After the first start remove the `broker.systems.*` settings; they are ignored from then on (a warning says so) and
   `read` on `secret/data/mcp/oauth-clients/*` can be dropped from the policy.
4. Without the old settings, nothing is imported: create the systems with `PUT /v1/admin/systems/{system}` through the portal.
   Mapping from the 1.x settings: `base-url` is `baseUrl`, `adapter`, `supported-types` and `default-type` keep their meaning,
   `secret-scheme` is `secretScheme`, `user-secret-scheme` is `userSecretScheme`, `oauth.client-id`, `oauth.authorize-url`,
   `oauth.token-url` and `oauth.revoke-url` are `oauth.clientId`, `oauth.authorizeUrl`, `oauth.tokenUrl` and `revokeUrl`,
   `oauth-scopes` is `oauth.scopes`. A `token-exchange` system puts the client of the IdP in `oauth` (`clientId`,
   `clientSecret`, `scopes`) and its `token-exchange.audience` in `exchangeAudience`.

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
  `503 upstream_unavailable` before it takes a database connection, and does not count as an attempt, so a
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
