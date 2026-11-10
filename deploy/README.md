# Install mcp-credential-broker

The credential broker with its own PostgreSQL and Redis on one Linux host with Docker. To install it together with the gateway, portal and identity provider, use the Compose bundle in `mcp-platform` instead. The steps below are for a broker on its own.

## Requirements

- Linux, Docker Engine with Compose v2.20 or newer, 1 GiB of memory.
- From your internal CA: a certificate for the broker (CN `mcp-credential-broker`, SAN `mcp-credential-broker.internal`, for server use) and the CA certificate.
- An OpenBao that you can administer.
- The address of the identity provider, the address of the gateway and the public address of the portal.

## Install

1. Prepare OpenBao once, as an administrator (`BAO_ADDR` and `BAO_TOKEN` set for the `bao` command). Skip the lines for what already exists. Never recreate a Transit key: what it encrypted is lost with it.

    ```bash
    bao secrets enable -path=secret -version=2 kv
    bao secrets enable transit
    bao write -f transit/keys/mcp-credential-broker type=aes256-gcm96
    bao write -f transit/keys/mcp-authenticators type=aes256-gcm96

    bao policy write mcp-credential-broker - <<'HCL'
    path "secret/data/mcp/connections/*"     { capabilities = ["create", "read", "update", "delete"] }
    path "secret/metadata/mcp/connections/*" { capabilities = ["read", "list", "delete"] }
    path "secret/data/mcp/system-clients/*"     { capabilities = ["create", "read", "update"] }
    path "secret/metadata/mcp/system-clients/*" { capabilities = ["read"] }
    path "secret/destroy/mcp/system-clients/*"  { capabilities = ["update"] }
    path "secret/data/mcp/oauth-clients/*"      { capabilities = ["read"] }
    path "secret/data/mcp/service-accounts/*"   { capabilities = ["read"] }
    path "transit/encrypt/mcp-credential-broker" { capabilities = ["update"] }
    path "transit/decrypt/mcp-credential-broker" { capabilities = ["update"] }
    path "secret/data/mcp/authenticators/*"     { capabilities = ["create", "read", "update", "delete"] }
    path "secret/metadata/mcp/authenticators/*" { capabilities = ["read", "list", "delete"] }
    path "transit/encrypt/mcp-authenticators" { capabilities = ["update"] }
    path "transit/decrypt/mcp-authenticators" { capabilities = ["update"] }
    HCL

    bao auth enable approle
    bao write auth/approle/role/mcp-credential-broker token_policies=mcp-credential-broker token_ttl=1h token_max_ttl=4h
    bao read -field=role_id auth/approle/role/mcp-credential-broker/role-id
    bao write -f -field=secret_id auth/approle/role/mcp-credential-broker/secret-id
    ```

    The last two commands print the `role_id` and the `secret_id` for `broker.env`. The AppRole has no `secret_id_ttl`, because the broker logs in with one `secret_id` whenever its token ends.

2. Build the stores in `certs/`. Use one password for all of them:

    | File | What |
    | --- | --- |
    | `keystore.p12` | the broker certificate and its key |
    | `truststore.p12` | the internal CA only: it decides which callers are accepted on port 8443 |
    | `outbound-truststore.p12` | optional: the internal CA and every other CA of the identity provider, OpenBao or the target systems |

    ```bash
    openssl pkcs12 -export -inkey broker.key -in broker.crt -certfile ca.crt -name mcp-credential-broker -out certs/keystore.p12
    keytool -importcert -noprompt -alias ca -file ca.crt -keystore certs/truststore.p12 -storetype PKCS12
    ```

3. If the identity provider, OpenBao or a target system uses a company or public CA, build the outbound store and set `MCP_TLS_OUTBOUND_TRUSTSTORE` in `broker.env`:

    ```bash
    keytool -importcert -noprompt -alias ca -file ca.crt -keystore certs/outbound-truststore.p12 -storetype PKCS12
    keytool -importcert -noprompt -alias company-ca -file company-ca.crt -keystore certs/outbound-truststore.p12 -storetype PKCS12
    ```

4. Fill in the empty values in `broker.env`: `MCP_PORTAL_URL`, `MCP_OIDC_ISSUER`, `MCP_OIDC_JWKS_URI`, `MCP_BAO_ADDR`, `MCP_BAO_ROLE_ID`, `MCP_BAO_SECRET_ID`, `MCP_GATEWAY_JWKS_URI` and `MCP_TLS_STORE_PASSWORD`.

5. Start the broker:

    ```bash
    docker compose up -d
    ```

6. Read the check that `init` runs before every start:

    ```bash
    docker compose logs init
    ```

On the first start `init` generates the passwords of PostgreSQL and Redis and the Redis configuration, and keeps them in Docker volumes.

## Check that it works

```bash
docker compose ps
```

Expected: the `broker` service is `healthy`. The listener demands a client certificate, so a plain `curl` to port 8443 is refused.

## Add the broker to the platform

1. Point the gateway at it: `MCP_BROKER_URL=https://<this host>:8443` and `MCP_BROKER_TLS_NAME=mcp-credential-broker.internal`.
2. Point the portal at it: `PORTAL_BROKER_URL` and `PORTAL_BROKER_TLS_NAME`.
3. Both present a client certificate from the internal CA: CN `mcp-gateway` and CN `mcp-portal-bff`.
4. An administrator adds the target systems in the portal, Administration, Systems.

## Common problems

| Symptom | Cause | Fix |
| --- | --- | --- |
| `init`: `FAIL OpenBao ...: AppRole login refused (HTTP 400)` | `MCP_BAO_ROLE_ID` or `MCP_BAO_SECRET_ID` is wrong, or the `secret_id` has expired | Write a new `secret_id` (see Rotate the secret_id) |
| `init`: `warn gateway keys ...: the name does not resolve` | DNS or `/etc/hosts` of this host, or the gateway is not installed yet | Fix the name; the broker starts anyway |
| `init` warns that the AppRole policy lacks a right | The policy differs from step 1 | Write the policy again |
| The broker answers `503` to the first request | The KV mount or a Transit key is missing (`init` does not probe them) | Run the commands of step 1 that were skipped |

## Ports

| Port | For |
| --- | --- |
| 8443 | TLS with the broker certificate, client certificate required. Set `BROKER_BIND` and `BROKER_PORT` in a `.env` file here to change the address and the host port. |

## Rotate the secret_id

Write a new one and replace it in `broker.env`, then run `docker compose up -d`:

```bash
bao write -f -field=secret_id auth/approle/role/mcp-credential-broker/secret-id
```

Once the broker runs, revoke the old one with `bao write auth/approle/role/mcp-credential-broker/secret-id/destroy secret_id=<old>`.

## Closed network

Copy the images to your registry and set them in a `.env` file next to `compose.yaml`:

```bash
MCP_REGISTRY=artifactory.corp.test/mcp
MCP_THIRD_PARTY_REGISTRY=artifactory.corp.test/dockerhub
```

## Upgrade

Change `MCP_BROKER_VERSION` in `.env` (or take the new directory) and run `docker compose up -d`. The generated passwords stay, and the schema is migrated when the broker starts.

## Virtual machine without Docker

`systemd/` has a unit and its environment file for a broker from the jar (`./mvnw package` makes `target/mcp-credential-broker.jar`),
with your own PostgreSQL and Redis. The Redis account of the broker needs the key prefixes, the channel and the commands of the ACL
that `init` writes for the Docker install (`redis-broker.rules` in the jar). The unit runs the same `init` before every start, without
generating anything: every password is in the environment file.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin broker
sudo install -d -o root -g broker -m 0750 /etc/mcp-credential-broker /opt/mcp-credential-broker
sudo install -m 0644 target/mcp-credential-broker.jar /opt/mcp-credential-broker/broker.jar
sudo install -o root -g broker -m 0640 systemd/mcp-credential-broker.env /etc/mcp-credential-broker/mcp-credential-broker.env
sudo install -m 0644 systemd/mcp-credential-broker.service /etc/systemd/system/
```

Fill in `/etc/mcp-credential-broker/mcp-credential-broker.env`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-credential-broker
```
