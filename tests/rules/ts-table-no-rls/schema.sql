create table public.open_table (id int, note text);
create table public.cfg (id int);
create table public.closed_table (id int, user_id uuid);
alter table public.closed_table enable row level security;
create policy "own" on public.closed_table for all to authenticated using ((select auth.uid()) = user_id);
create schema private;
create table private.hidden (id int);
