-- Metadata of user connections only. Secret values live in OpenBao (D6), never here.
create table connection (
    sub           varchar(255) not null,
    system        varchar(32)  not null,
    type          varchar(32)  not null,
    -- stored state; expiring and expired are derived from expires_at when read
    state         varchar(16)  not null check (state in ('connected', 'revoked', 'error')),
    backend_user  varchar(255) not null,
    expires_at    timestamptz,
    connected_at  timestamptz  not null,
    last_used_at  timestamptz,
    updated_at    timestamptz  not null,
    primary key (sub, system)
);
