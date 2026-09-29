-- Lab schema: intentionally vulnerable. Fake data only.

create schema if not exists private;

-- @lab decoy rls-missing cwe=CWE-862 lines=4 :: schema private tidak diekspos PostgREST
create table private.internal_notes (
  id bigint generated always as identity primary key,
  note text not null
);

-- @lab decoy rls-missing cwe=CWE-862 lines=7 :: RLS aktif
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  username text unique not null,
  full_name text,
  created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;

-- @lab decoy policy-true cwe=CWE-863 lines=3 :: policy berbasis pemilik
-- @lab decoy policy-no-uid cwe=CWE-863 lines=3 :: memakai auth.uid()
create policy "profiles_select_own" on public.profiles
  for select to authenticated
  using ((select auth.uid()) = id);

create policy "profiles_update_own" on public.profiles
  for update to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);

-- @lab decoy rls-missing cwe=CWE-862 lines=8 :: RLS aktif
create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  title text not null,
  body text,
  done boolean not null default false,
  priority int not null default 1
);
alter table public.todos enable row level security;

-- @lab decoy policy-no-uid cwe=CWE-863 lines=3 :: memakai auth.uid()
create policy "todos_all_own" on public.todos
  for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

-- @lab vuln rls-missing cwe=CWE-862 tier=A lines=6 :: tabel public tanpa RLS
create table public.audit_log (
  id bigint generated always as identity primary key,
  actor text,
  action text not null,
  at timestamptz not null default now()
);

-- @lab decoy rls-missing cwe=CWE-862 lines=6 :: RLS aktif
create table public.invoices (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id),
  amount_cents int not null,
  status text not null default 'open'
);
alter table public.invoices enable row level security;

-- @lab vuln policy-true cwe=CWE-863 tier=A lines=3 :: semua user terautentikasi bisa membaca semua invoice
create policy "invoices_select_all" on public.invoices
  for select to authenticated
  using (true);

-- @lab decoy policy-true cwe=CWE-863 lines=3 :: berbasis pemilik
create policy "invoices_insert_own" on public.invoices
  for insert to authenticated
  with check ((select auth.uid()) = user_id);

-- @lab decoy rls-missing cwe=CWE-862 lines=8 :: RLS aktif
create table public.messages (
  id bigint generated always as identity primary key,
  sender_id uuid references auth.users (id),
  body text not null,
  is_public boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.messages enable row level security;

-- @lab vuln policy-anon-write cwe=CWE-862 tier=A lines=3 :: anon boleh UPDATE
create policy "messages_anon_update" on public.messages
  for update to anon
  using (created_at > now() - interval '1 day');

-- @lab decoy policy-anon-write cwe=CWE-862 lines=3 :: anon hanya membaca data publik
create policy "messages_anon_select_public" on public.messages
  for select to anon
  using (is_public);

-- @lab decoy policy-true cwe=CWE-863 lines=3 :: berbasis pemilik
create policy "messages_insert_own" on public.messages
  for insert to authenticated
  with check ((select auth.uid()) = sender_id);

-- @lab decoy rls-missing cwe=CWE-862 lines=6 :: RLS aktif
create table public.documents (
  id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users (id),
  title text not null
);
alter table public.documents enable row level security;

-- @lab vuln policy-user-metadata cwe=CWE-285 tier=A lines=3 :: user_metadata dapat diubah oleh user
create policy "documents_admin_all" on public.documents
  for all to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

-- @lab decoy policy-user-metadata cwe=CWE-285 lines=3 :: app_metadata hanya bisa diubah server
create policy "documents_admin_app_metadata" on public.documents
  for select to authenticated
  using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

-- @lab decoy rls-missing cwe=CWE-862 lines=8 :: RLS aktif
create table public.projects (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id),
  name text not null,
  is_public boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.projects enable row level security;

-- @lab vuln policy-no-uid cwe=CWE-863 tier=B lines=3 :: tabel ber-user_id, policy tidak membatasi pemilik
create policy "projects_select_public" on public.projects
  for select to authenticated
  using (is_public);

-- @lab decoy policy-no-uid cwe=CWE-863 lines=3 :: memakai auth.uid()
create policy "projects_select_owner" on public.projects
  for select to authenticated
  using (is_public or (select auth.uid()) = user_id);

-- Dibuat tanpa RLS di sini; RLS diaktifkan di migration berikutnya (keadaan akhir aman).
-- @lab decoy rls-missing cwe=CWE-862 lines=4 :: RLS diaktifkan di migration 003
create table public.late_rls (
  id bigint generated always as identity primary key,
  note text
);

-- RLS + policy di sini; RLS dimatikan di migration 003 (keadaan akhir rentan).
create table public.reports (
  id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users (id),
  content text
);
alter table public.reports enable row level security;
create policy "reports_own" on public.reports
  for all to authenticated
  using ((select auth.uid()) = owner_id);

create table public.items (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id),
  name text not null
);
alter table public.items enable row level security;
create policy "items_own" on public.items
  for all to authenticated
  using ((select auth.uid()) = user_id);

create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id),
  status text not null default 'new'
);
alter table public.orders enable row level security;
create policy "orders_own" on public.orders
  for all to authenticated
  using ((select auth.uid()) = user_id);
