# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Use the private vulnerability reporting of the repository (the
"Security" tab, "Report a vulnerability"). Include the commit or image tag, the operation of the C4 API involved and a
request that shows the problem. Do not attach real secrets or tokens.

This repository has no bug bounty.

## What counts

- Any response other than `resolve` that carries the value of a stored secret, or a log or audit line that does.
- A way to read, change or delete the connection of another user (a substituted `sub` in the body or the path, a
  token of one user used for another, an OAuth link opened by someone else).
- A caller without the right client certificate CN or token for an operation that still gets through.
- A request that makes the broker answer with a secret after the secret store, the database or Redis failed
  (the broker is meant to fail closed).
- A stored value that survives `DELETE` or `purge`, or a connection that comes back after a purge.

## Not in scope

The published test keys of `mcp-contracts` are refused unless `MCP_ALLOW_TEST_KEYS=true`, and keys with a `dev-` `kid`
also need the `devstack` Spring profile; findings that need them enabled in production are configuration errors. The development stack credentials
(`mcp-platform-dev`) are not production credentials.

## Supported versions

The `main` branch and the latest tagged image.
