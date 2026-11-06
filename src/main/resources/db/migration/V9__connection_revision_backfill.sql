-- A connection without a client revision matches no definition of its system (it could be used after the system was pointed
-- somewhere else). Connections of systems that are rows already get the revision of their system; the ones of 1.x get it when
-- the import stores their system.
update connection c
   set client_revision = s.client_revision
  from target_system s
 where s.id = c.system
   and c.client_revision is null;
