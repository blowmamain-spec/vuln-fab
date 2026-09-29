create table public.t (id int);
alter table public.t enable row level security;
create policy "admin" on public.t for all to authenticated using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
create policy "auth_only" on public.t for select to authenticated using (auth.uid() is not null);
