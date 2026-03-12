-- supabase_schema.sql
-- Run this once in your Supabase project:
--   Supabase dashboard → SQL Editor → paste & run
-- ─────────────────────────────────────────────────────────────────────────────

create table if not exists alerts (
  id            bigserial    primary key,
  ts            bigint       not null,          -- JS epoch milliseconds
  level         text         not null,          -- 'HighAlert' | 'Suspicious'
  label         text         not null,          -- 'Malicious'  | 'Suspicious'
  confidence    real         not null,
  pid           integer,
  remote_ip     text,
  remote_port   integer,
  actions_taken jsonb        default '[]'::jsonb,
  created_at    timestamptz  default now()
);

-- Fast recent-first lookups used by the API
create index if not exists idx_alerts_ts on alerts (ts desc);

-- Row Level Security
alter table alerts enable row level security;

-- Allow the anon role to read (React UI uses the anon key)
create policy "anon_read" on alerts
  for select
  using (true);

-- Only the service-role key (used by api_server.py) may write
create policy "service_write" on alerts
  for insert
  with check (true);

create policy "service_delete" on alerts
  for delete
  using (true);
