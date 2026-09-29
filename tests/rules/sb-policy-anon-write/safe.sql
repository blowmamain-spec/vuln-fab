create table public.t (id int, is_public boolean, owner_id uuid);
alter table public.t enable row level security;
create policy "anon_read" on public.t for select to anon using (is_public);
create policy "auth_write" on public.t for insert to authenticated with check (auth.uid() = owner_id);
create policy "anon_owner" on public.t for update to anon using (auth.uid() = owner_id);
create policy "anon_false" on public.t for delete to anon using (false);
create policy "restrictive" on public.t as restrictive for insert to anon with check (true);
create policy "storage_objects" on storage.objects for insert to public with check (bucket_id = 'x');
