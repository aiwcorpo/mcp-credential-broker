# Install the credential broker

The credential broker with its own PostgreSQL and Redis on one Linux host with Docker. The other components (identity provider,
OpenBao, gateway, portal) run elsewhere; you give the addresses of the first three here, and the gateway and the portal are pointed at
the broker afterwards.

## Prerequisites

- Linux, Docker Engine with Compose v2.20 or newer, 1 GiB of memory for the broker.
- From your internal CA: a certificate for the broker with CN `mcp-credential-broker` and SAN `mcp-credential-broker.internal`, for
  server use, and the CA certificate.
- OpenBao prepared as described in the next section.
- The address of the identity provider, of the gateway and the public address of the portal.

The broker trusts only `certs/truststore.p12` for every connection it opens: the identity provider, OpenBao and the gateway. The same
store decides which client certificates are accepted on port 8443. So the CA that signed the certificates of those three must be in
it, and every CA in it can issue callers of the broker (each caller is still tied to its certificate name, `mcp-gateway`,
`mcp-portal-bff`, `mcp-offboarding`). If the identity provider has a certificate from a public or company CA, you are deciding to add
that CA to the store.

## OpenBao

The broker keeps the credentials of users and the seeds of the Authenticator in OpenBao: values in KV v2, encryption keys in Transit.
Once, as an administrator of OpenBao (`BAO_ADDR` and `BAO_TOKEN` set for the `bao` command):

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

Skip the lines for what already exists (a KV mount at `secret/`, the auth method, the keys). Never recreate a Transit key: what it
encrypted is lost with it. The last two commands print the `role_id` and the `secret_id` for `broker.env`. The broker keeps one
`secret_id` and logs in with it whenever its token ends, so the AppRole has no `secret_id_ttl`. If you set one, replace the `secret_id`
before it ends (see Rotate the secret_id).

## Install

1. Get this directory (`deploy/` of the repository) on the host and change into it.
2. Put two files in `certs/`:

    | File | What |
    | --- | --- |
    | `keystore.p12` | the broker certificate and its key |
    | `truststore.p12` | the internal CA certificate (and the CA of the identity provider and of OpenBao, when another) |

    Both stores use one password. From PEM files:

    ```bash
    openssl pkcs12 -export -inkey broker.key -in broker.crt -certfile ca.crt -name mcp-credential-broker -out certs/keystore.p12
    keytool -importcert -noprompt -alias ca -file ca.crt -keystore certs/truststore.p12 -storetype PKCS12
    ```

3. Fill in the empty values in `broker.env`.
4. Start:

    ```bash
    docker compose up -d
    ```

The `init` service runs before the broker on every start. On the first start it generates the passwords of PostgreSQL and Redis and
the Redis configuration, and keeps them in Docker volumes. The ACL of Redis gives the broker its own key prefixes (`broker:*`,
`jti:mcp-credential-broker:*`), its one channel (`credential.invalidated`) and the commands it uses, and holds only the SHA-256 of
the password. Then `init` checks the configuration and the connections the way the broker will use them:

```console
$ docker compose logs init
ok    BFF clients: mcp-portal-bff
ok    broker certificate /certs/keystore.p12 and truststore /certs/truststore.p12
ok    identity provider keys https://idp.corp.test/realms/corp/protocol/openid-connect/certs
FAIL  OpenBao https://openbao.corp.test:8200: AppRole login refused (HTTP 400): MCP_BAO_ROLE_ID or MCP_BAO_SECRET_ID is wrong, or the secret_id has expired
warn  gateway keys https://mcp-gateway.corp.test:8443/.well-known/jwks.json: the name does not resolve from this host (DNS or /etc/hosts)
```

A `FAIL` stops the start: fix it and run `docker compose up -d` again. A `warn` does not, because the gateway may be installed after
the broker. `init` also warns when the policy of the AppRole lacks a right the broker uses; the KV mount and the Transit keys are not
probed, so check them with the commands above if the broker answers `503` to the first request.

The files `init` shares with PostgreSQL and Redis (the database password, `users.acl`, `redis.conf`) are mode 0640, owned by the
broker's group (gid 10001). They are in volumes that only `init` and that one container mount, and the Redis container joins the group
(`group_add`), so nothing runs as root and the files are not readable by anyone else.

## The gateway and the portal

Point the gateway at the broker with `MCP_BROKER_URL` (`https://<this host>:8443`) and `MCP_BROKER_TLS_NAME=mcp-credential-broker.internal`,
and the portal with `PORTAL_BROKER_URL` and `PORTAL_BROKER_TLS_NAME`. Both present a client certificate from the internal CA: CN
`mcp-gateway` and CN `mcp-portal-bff`. The systems the broker resolves credentials for are not settings: the administrator adds
them in the administration of the portal.

## Ports

| Port | For |
| --- | --- |
| 8443 | TLS with the broker certificate, client certificate required: the gateway and the portal. Set `BROKER_BIND` and `BROKER_PORT` in a `.env` file here to change the address and the host port. |

## Rotate the secret_id

Write a new one and replace it in `broker.env`, then `docker compose up -d`. The broker logs in again at the start:

```bash
bao write -f -field=secret_id auth/approle/role/mcp-credential-broker/secret-id
```

Revoke the old one with `bao write auth/approle/role/mcp-credential-broker/secret-id/destroy secret_id=<old>` once the broker runs.

## Closed network

Copy the images to your registry and point Compose at it in a `.env` file next to `compose.yaml`:

```bash
MCP_REGISTRY=artifactory.corp.test/mcp
MCP_THIRD_PARTY_REGISTRY=artifactory.corp.test/dockerhub
```

## Upgrade

Change `MCP_BROKER_VERSION` in `.env` (or take the new directory) and run `docker compose up -d`. The generated passwords stay, and the
schema is migrated when the broker starts.

## Virtual machine without Docker

`systemd/` has a unit and its environment file for a broker from the jar (`./mvnw package` makes `target/mcp-credential-broker.jar`),
with your own PostgreSQL and Redis. The Redis account of the broker needs the key prefixes, the channel and the commands of the ACL
that `init` writes for the Docker install (`redis-broker.rules` in the jar). The unit runs the same `init` before every start, without
generating anything: every password is in the environment file.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin broker
sudo install -d -o root -g broker -m 0750 /etc/mcp-credential-broker /opt/mcp-credential-broker
sudo install -m 0644 target/mcp-credential-broker.jar /opt/mcp-credential-broker/broker.jar
sudo install -o root -g broker -m 0640 systemd/mcp-credential-broker.env /etc/mcp-credential-broker/mcp-credential-broker.env   # then fill it in
sudo install -m 0644 systemd/mcp-credential-broker.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now mcp-credential-broker
```

If `init` ever wrote files for a database or Redis there, they would still be unreachable for other users: the state directory is
mode 0700 (`StateDirectoryMode`) and the unit's `UMask=0077` keeps what is below it closed.
