-- When the current OAuth access token stops working; null for user-secret. Kept apart from expires_at, which
-- is the date a user gave for a PAT and drives the C4 status.
alter table connection add column access_expires_at timestamptz;
create index connection_oauth_refresh on connection (access_expires_at) where type = 'user-oauth' and state = 'connected';
