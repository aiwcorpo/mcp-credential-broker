-- A system being deleted is withdrawn first: no instance serves it and no admin read shows it from then on, so a delete
-- that fails while it removes the connections leaves the system out of service. A repeated DELETE finishes the job.
alter table target_system add column withdrawn_at timestamptz;
