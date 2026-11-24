-- CC-261: whether an autonomous agent (pty agent in the internal JWT) may be handed the shared service-account credential.
-- Off for every system that exists today; only the admin API turns it on, and only for a system with service-account.
alter table target_system add column agents_allowed boolean not null default false;
