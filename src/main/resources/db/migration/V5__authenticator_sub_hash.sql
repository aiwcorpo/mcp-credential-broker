-- The hash of sub names the seed in OpenBao (mcp/authenticators/<sha256(sub)>). Kept next to sub so that the sweep
-- can tell, from a path alone, whether a stored seed still belongs to a registration or to an enrollment.
alter table authenticator add column sub_hash varchar(64);
update authenticator set sub_hash = encode(sha256(convert_to(sub, 'UTF8')), 'hex');
alter table authenticator alter column sub_hash set not null;
create unique index authenticator_sub_hash on authenticator (sub_hash);
