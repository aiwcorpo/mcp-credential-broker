# Changelog

The broker ships as a container image (`ghcr.io/aiwcorpo/mcp-credential-broker`); the version in `pom.xml` follows SemVer. Local and
integration builds tag the image `m6-<short sha>`.

## 2.0.0

Built on `mcp-contracts` 7.0.0. Breaking: the systems are no longer configuration.

- Systems live in PostgreSQL (table `target_system`, migration `V7`) and are managed through the admin API of C4:
  `GET /v1/admin/systems`, `GET`, `PUT` and `DELETE /v1/admin/systems/{system}`. Callers are the portal BFF (certificate
  CN `mcp-portal-bff`) with the token of a user in the group `mcp-platform-admin` (claim `groups`); anything else is
  `403`. A create sends `If-None-Match: *`, a replace sends `If-Match` with the `ETag` of the last read (`412` when it is
  stale, `428` when neither is sent). The response never carries a secret, only `clientSecretSet`.
- Per system the adapter is chosen: `atlassian-dc`, `gitlab`, `opensearch` or `generic-rest`. The checks of the 1.x
  start-up now answer `422 system_rejected` with a reason: `adapter_type_mismatch`, `credential_types_mixed`,
  `default_type_not_supported`, `oauth_required`, `secret_scheme_not_supported`, `system_reserved`,
  `client_secret_required`. Ids follow `SystemId`: `^[a-z][a-z0-9]{1,30}$`, without the reserved names `gateway`,
  `offboarding`, `portal`, `broker`, `prometheus`, `platform`, `admin`, `registry`, `adapter`, `internal`, `ci`.
- The OAuth client secret (also the secret of the IdP client of a `token-exchange` system) is written to OpenBao at
  `<kv-mount>/data/<oauth-clients-prefix>/<system>`, field `client_secret` (by default `secret/data/mcp/oauth-clients/<system>`,
  the path 1.x already read). A PUT without a secret keeps it only while `baseUrl`, `oauth.authorizeUrl`, `oauth.tokenUrl` and
  `oauth.clientId` are unchanged. **The AppRole policy of the broker must now allow `create`, `read`, `update` and `delete`
  on `secret/data/mcp/oauth-clients/*` and `read` and `delete` on `secret/metadata/mcp/oauth-clients/*`** (it was read only).
- Every instance polls the table (`broker.system-sync.interval`, 5 s by default) and swaps its list of systems, so a change
  made on any instance is visible on all of them within about that interval, without a restart; the instance that took the
  write reloads at once. Polling was chosen over Redis pub/sub because a lost message would leave an instance on an old list
  until the next restart, and the broker's Redis account may publish only `credential.invalidated`. The cached client secret
  is keyed by the revision of the system, so a rotation is read again on every instance after that poll.
- `DELETE` removes the connections of users to the system and their stored values (each removal publishes
  `credential.invalidated` and writes `connection_change` with reason `system_deleted`), then the row and the client secret.
  It is idempotent and can be repeated after a failure. A broker instance that has not yet seen the deletion can accept a
  connection for the removed system during one poll interval; repeat the `DELETE` to remove it.
- `GET /v1/systems` reads the stored systems. `resolve` for an id nobody configured answers `422 system_not_configured`;
  a connection whose credential type the system no longer supports is listed with status `error` and `resolve` asks the user
  to connect again.
- Every change writes an `admin_change` event with reason `system_created`, `system_updated` or `system_deleted`
  (`denied` with the reason of the refusal, such as `precondition_failed` or `not_admin`), the administrator as `sub` and
  the system as `server`. The audit field `policyRevision` and the claim `prv` of the internal JWT are integers (CC-237).
- `atlassian-dc` no longer knows whether it talks to Jira or Confluence from the id of the system: the first `whoami` tries
  Jira's path and, on `404`, Confluence's, and remembers the product that answered.
- **Removed:** the list of known systems in the code (`SystemRegistry.KNOWN_SYSTEMS`) and the `broker.systems` block of
  `application.yml`. `MCP_JIRA_URL` and the other per system variables are no longer required.

### Moving from 1.x

1. Back up PostgreSQL, and give the AppRole of the broker the policy above.
2. Keep the `BROKER_SYSTEMS_*` (or `broker.systems.*`) settings of 1.x for the first start of 2.0.0. When the table is empty
   and nothing was imported before, the broker stores those systems once (one `admin_change` event `system_imported` each) and
   remembers that it did (table `target_system_import`), so that deleting every system later does not bring them back.
   Client secrets are not copied: the secret at `mcp/oauth-clients/<system>`, which 1.x already required, is used as it is;
   a dev only `oauth.client-secret` property is written to OpenBao once. Fields that the admin API does not have (`timeout`,
   OAuth `revoke-url`, `deployment`, the token exchange `audience`) are imported and kept when the system is replaced
   through the API. `user-secret-scheme` is folded into `secret-scheme` for a system that takes only `user-secret`.
3. After the first start remove the `broker.systems.*` settings; they are ignored from then on (a warning says so).
4. Without the old settings, or on a table that already has systems, nothing is imported: create the systems with
   `PUT /v1/admin/systems/{system}` through the portal. Mapping from the 1.x settings: `base-url` is `baseUrl`, `adapter`,
   `supported-types` and `default-type` keep their meaning, `secret-scheme` is `secretScheme`, `oauth.client-id`,
   `oauth.authorize-url` and `oauth.token-url` are the same fields of `oauth`, `oauth-scopes` is `oauth.scopes`. A
   `token-exchange` system puts the client of the IdP in `oauth` (`clientId`, `clientSecret`, `tokenUrl`, `scopes`;
   `authorizeUrl` is required by the contract and unused) and takes the system id as the audience.

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
