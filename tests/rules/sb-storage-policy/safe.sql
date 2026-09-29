create policy "own_upload" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "own_update" on storage.objects for update to authenticated using (owner = auth.uid());
create policy "public_read" on storage.objects for select using (bucket_id = 'avatars');
create policy "service" on storage.objects for insert to service_role with check (true);
create policy "restrictive" on storage.objects as restrictive for insert to public with check (bucket_id = 'x');
