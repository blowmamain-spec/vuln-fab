create table public.projects (id int, user_id uuid, is_public boolean, status text);
alter table public.projects enable row level security;
create policy "pub" on public.projects for select to authenticated using (is_public);  -- vuln: sb-policy-no-uid
create policy "status_ok" on public.projects for select to authenticated using (status = 'published');  -- vuln: sb-policy-no-uid
create policy "anon_read" on public.projects for select to anon using (is_public and status = 'ok');  -- vuln: sb-policy-no-uid
