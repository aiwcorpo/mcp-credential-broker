# Contributing

Changes go through a pull request. Read the README section "Build and test" first.

- Run `./mvnw -B verify` before pushing. It needs JDK 25 and a container runtime for the integration tests (Testcontainers);
  on Windows use WSL2. `-Dtest='!*IntegrationTest'` runs only the tests that need no containers.
- The API and the audit events follow `mcp-contracts` (`openapi/credential-broker.v1.yaml`, `schemas/audit-event.schema.json`).
  A change of an operation, a status code or a reason is made there first (`CONTRACT_CHANGES.md`); here you bump
  `mcp-contracts.version` and follow it.
- Do not put secret values in logs, audit events or error bodies; the tests check all of them.
- Commits: English subject up to 72 characters in the imperative mood, a body that describes the change.
- Never commit key material, `.env` files or the output of a build.
