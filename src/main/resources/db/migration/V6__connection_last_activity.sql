-- The cleanup of unused connections (CC-155) selects by the last use, or by the creation when the connection was never used.
create index connection_last_activity on connection ((coalesce(last_used_at, connected_at)));
