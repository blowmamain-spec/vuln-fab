create table public.t (id int);
alter table public.t enable row level security;
create policy "admin" on public.t for all to authenticated using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');  -- vuln: sb-policy-user-metadata
create policy "meta_check" on public.t for insert to authenticated with check ((select auth.jwt() -> 'user_metadata' ->> 'plan') = 'pro');  -- vuln: sb-policy-user-metadata
create policy "legacy" on public.t for select using (raw_user_meta_data ->> 'admin' = 'true');  -- vuln: sb-policy-user-metadata
