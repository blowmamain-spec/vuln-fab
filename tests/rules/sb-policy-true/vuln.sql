create table public.t (id int, user_id uuid);
alter table public.t enable row level security;
create policy "all_read" on public.t for select to authenticated using (true);  -- vuln: sb-policy-true
create policy "anyone_insert" on public.t for insert with check (true);  -- vuln: sb-policy-true
create policy "everything" on public.t for all to anon using (true) with check (true);  -- vuln: sb-policy-true
create policy "one_eq_one" on public.t for select using (1 = 1);  -- vuln: sb-policy-true
