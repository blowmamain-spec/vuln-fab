create policy "any_upload" on storage.objects for insert to public with check (bucket_id = 'invoices');  -- vuln: sb-storage-policy
create policy "any_update" on storage.objects for update to authenticated using (bucket_id = 'docs');  -- vuln: sb-storage-policy
create policy "any_delete" on storage.objects for delete to authenticated using (bucket_id = 'docs');  -- vuln: sb-storage-policy
