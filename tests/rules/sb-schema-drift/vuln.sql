create table public.a (id int);
alter table public.a enable row level security;  -- vuln: sb-schema-drift
create table public.b (id int);  -- vuln: sb-schema-drift
alter table public.b enable row level security;
create policy "p_mig" on public.b using (true);
create table public.gone (id int);  -- vuln: sb-schema-drift
