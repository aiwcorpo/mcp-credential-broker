-- Metadata of the TOTP authenticator (C4, CC-091, CC-092, CC-126). The seed is never here: it lives in OpenBao,
-- encrypted by Transit, under mcp/authenticators/<sha256(sub)>.
-- One row per user, also while the user has no registration, because a lock after repeated wrong codes belongs
-- to the user and survives removal and a new registration (CC-091). Every change goes through
-- "select ... for update" on this row, which is what makes the counters and the lock one atomic step per sub.
create table authenticator (
    sub                 varchar(255) primary key,
    state               varchar(16)  not null check (state in ('none', 'active', 'disabled')),
    registration_id     varchar(32),
    registered_at       timestamptz,
    last_used_at        timestamptz,
    last_accepted_step  bigint,
    burned_through      bigint,
    locked_until        timestamptz,
    disabled_at         timestamptz,
    pending_id          varchar(128),
    pending_created_at  timestamptz,
    pending_wrong_codes integer      not null default 0,
    enroll_window_start timestamptz,
    enroll_starts       integer      not null default 0,
    updated_at          timestamptz  not null
);

-- Wrong codes of the last 24 hours. in_short_window marks those that still count toward the 5-in-15-minutes
-- limit: a success or the end of a lock clears the mark but not the row, because the daily counter keeps them.
create table authenticator_failure (
    id              bigserial primary key,
    sub             varchar(255) not null references authenticator (sub) on delete cascade,
    at              timestamptz  not null,
    in_short_window boolean      not null default true
);
create index authenticator_failure_sub_at on authenticator_failure (sub, at);
