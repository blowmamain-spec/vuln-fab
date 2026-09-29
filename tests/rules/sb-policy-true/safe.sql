create table public.t (id int, user_id uuid);
alter table public.t enable row level security;
create policy "own" on public.t for select to authenticated using ((select auth.uid()) = user_id);
create policy "own_write" on public.t for insert to authenticated with check (auth.uid() = user_id);
create policy "closed" on public.t for select using (false);
create policy "service" on public.t for all to service_role using (true);
create policy "restrictive_true" on public.t as restrictive for select to authenticated using (true);
create policy "flag" on public.t for select using (id > 0);
