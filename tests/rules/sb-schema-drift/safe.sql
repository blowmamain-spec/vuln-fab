create table public.a (id int);
alter table public.a enable row level security;
create policy "p" on public.a using (true);
create table private.hidden (id int);
