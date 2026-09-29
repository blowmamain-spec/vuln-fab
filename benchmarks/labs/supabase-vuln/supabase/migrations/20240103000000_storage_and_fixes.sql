-- @lab vuln storage-public cwe=CWE-200 tier=A :: bucket invoices publik
insert into storage.buckets (id, name, public) values ('invoices', 'invoices', true);

-- @lab decoy storage-public cwe=CWE-200 :: avatar memang publik
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);

-- @lab decoy storage-public cwe=CWE-200 :: bucket privat
insert into storage.buckets (id, name, public) values ('contracts', 'contracts', false);

-- @lab vuln storage-policy cwe=CWE-863 tier=A lines=2 :: siapa pun bisa upload ke bucket invoices
create policy "invoices_any_upload" on storage.objects
  for insert to public with check (bucket_id = 'invoices');

-- @lab decoy storage-policy cwe=CWE-863 lines=4 :: dibatasi folder milik user
create policy "avatars_own_upload" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'avatars'
    and (storage.foldername(name))[1] = (select auth.uid())::text);

-- RLS untuk late_rls diaktifkan di sini: keadaan akhir aman.
alter table public.late_rls enable row level security;
create policy "late_rls_own" on public.late_rls for all to authenticated
  using (false);

-- @lab vuln rls-missing cwe=CWE-862 tier=A :: RLS dimatikan; keadaan akhir tanpa RLS
alter table public.reports disable row level security;
