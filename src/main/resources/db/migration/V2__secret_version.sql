-- Path segment of the stored value written by the last PUT; null for values stored by V1 (no segment).
alter table connection add column secret_version varchar(64);
