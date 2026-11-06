-- Admin systems after the security review (CC-238).
-- product: which Atlassian product an atlassian-dc system is; the broker never detects it.
alter table target_system add column product text;

-- The KV version of the client secret that goes with this row. A reader asks for exactly this version, so a secret written
-- by a concurrent change is never read with the configuration of another one. client_secret_set is derived from it.
alter table target_system add column secret_version integer;
update target_system set secret_version = 1 where client_secret_set;
alter table target_system drop column client_secret_set;

-- Moves only when the system points somewhere else (baseUrl, authorizeUrl, tokenUrl, clientId, revokeUrl). A grant records
-- the revision it was issued under, and nothing is sent to a provider with a definition other than that one.
alter table target_system add column client_revision text;
update target_system set client_revision = etag;
alter table target_system alter column client_revision set not null;

alter table connection add column client_revision text;
alter table connection drop constraint connection_state_check;
alter table connection add constraint connection_state_check
    check (state in ('connected', 'revoked', 'error', 'needs_reconnect'));

-- A write of a stale instance for a system that was deleted fails instead of leaving a connection nobody can clean up.
-- NOT VALID: connections written by 1.x, before the systems were rows, stay as they are.
alter table connection add constraint connection_system_fk
    foreign key (system) references target_system (id) on delete restrict not valid;
