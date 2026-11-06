-- generic-rest systems can take user secrets (CC-247). With a whoami the secret is verified when it is stored; without
-- one it is stored unverified and the connection has no backend user.
alter table target_system add column whoami_path text;
alter table target_system add column whoami_username_field text;

alter table connection alter column backend_user drop not null;
alter table connection add column verified boolean not null default true;
