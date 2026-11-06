-- Target systems are runtime data (7.0.0 contracts): managed through /v1/admin/systems, read by every instance.
-- The OAuth client secret is never stored here; it lives in OpenBao and client_secret_set only says that it was written.
-- timeout_ms, oauth_revoke_url, user_secret_scheme, deployment and exchange_audience are not part of the admin API: they
-- come from the one-time import of the 1.x properties and are carried over unchanged when a system is replaced.
create table target_system (
    id                  text primary key,
    base_url            text        not null,
    adapter             text        not null,
    supported_types     jsonb       not null,
    default_type        text        not null,
    secret_scheme       text        not null,
    oauth_client_id     text,
    oauth_authorize_url text,
    oauth_token_url     text,
    oauth_revoke_url    text,
    oauth_scopes        jsonb       not null default '[]'::jsonb,
    client_secret_set   boolean     not null default false,
    exchange_audience   text,
    user_secret_scheme  text,
    deployment          text,
    timeout_ms          integer,
    etag                text        not null,
    created_at          timestamptz not null,
    updated_at          timestamptz not null
);

-- A single row once the 1.x properties were imported, so that deleting every system later does not bring them back.
create table target_system_import (
    only_row    boolean primary key default true check (only_row),
    imported_at timestamptz not null
);
