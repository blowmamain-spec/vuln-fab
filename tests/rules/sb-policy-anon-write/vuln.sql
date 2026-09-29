create table public.t (id int, created_at timestamptz, owner_id uuid);
alter table public.t enable row level security;
create policy "anon_insert" on public.t for insert to anon with check (true);  -- vuln: sb-policy-anon-write
create policy "anon_update" on public.t for update to anon using (created_at > now() - interval '1 day');  -- vuln: sb-policy-anon-write
create policy "public_delete" on public.t for delete using (id > 0);  -- vuln: sb-policy-anon-write
create policy "anon_all" on public.t for all to anon using (true);  -- vuln: sb-policy-anon-write
