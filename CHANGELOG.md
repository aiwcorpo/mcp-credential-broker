# Changelog

The broker ships as a container image (`mcp-credential-broker`); the version in `pom.xml` follows SemVer and the
image tag names the milestone and the commit (`m6-<short sha>`).

## Unreleased

- Contracts `mcp-contracts` 6.2.0.
- Infrastructure failures while checking the gateway token are audited as event `authentication`, outcome `denied`,
  `errorCode: upstream_unavailable`, with reason `jwks_unavailable` (keys) or `replay_store_unavailable` (Redis).
  They were `key_source_unavailable` and `jti_store_unavailable` as the event of the operation with outcome `error`
  (CC-197). The response stays `503 upstream_unavailable`.
- A connection whose secret is gone from the secret store goes to state `error` and emits `connection_change` with
  reason `secret_missing` once (CC-205). `resolve` and the refresh sweep both do it. A row in `error` no longer
  occupies the sweep batch; connecting again restores `connected`. Portals show it as `error`.
- Marking lost secrets as `error` deletes nothing in the secret store and has a brake: after `broker.lost-secret-brake.max-marks`
  (10) marks within `broker.lost-secret-brake.window` (10 min) it stops marking, keeps answering `credential_required`,
  logs one alarm per window and counts `broker.connection.secret_missing_brake`.
- Audit reason `user_offboarding` has outcome `denied`, as the contract describes it (it was `error`).
- Housekeeping for the public release: Apache-2.0 (LICENSE, NOTICE, license in `pom.xml`), SECURITY.md,
  CONTRIBUTING.md, SBOM profile `release`, release workflow for ghcr.io (not run), portable build instructions, image tag prefix `m6-`.
