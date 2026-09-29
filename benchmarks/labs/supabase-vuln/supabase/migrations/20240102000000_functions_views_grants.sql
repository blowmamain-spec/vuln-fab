-- @lab vuln definer-no-path cwe=CWE-426 tier=A lines=7 :: SECURITY DEFINER tanpa search_path
create function public.get_user_data(uid uuid)
returns setof public.profiles
language sql
security definer
as $$
  select * from public.profiles where id = uid
$$;

-- @lab decoy definer-no-path cwe=CWE-426 lines=8 :: search_path dikunci
create function public.get_my_profile()
returns setof public.profiles
language sql
security definer
set search_path = ''
as $$
  select * from public.profiles where id = (select auth.uid())
$$;

-- @lab vuln dynamic-sql cwe=CWE-89 tier=A lines=9 :: EXECUTE dengan konkatenasi parameter
create function public.search_items(term text)
returns setof public.items
language plpgsql
security invoker
set search_path = ''
as $$
begin
  return query execute 'select * from public.items where name = ''' || term || '''';
end;
$$;

-- @lab decoy dynamic-sql cwe=CWE-89 lines=9 :: format(%L) meng-quote parameter
create function public.search_items_safe(term text)
returns setof public.items
language plpgsql
security invoker
set search_path = ''
as $$
begin
  return query execute format('select * from public.items where name = %L', term);
end;
$$;

-- @lab decoy dynamic-sql cwe=CWE-89 lines=9 :: parameter terikat lewat USING
create function public.search_items_bound(term text)
returns setof public.items
language plpgsql
security invoker
set search_path = ''
as $$
begin
  return query execute 'select * from public.items where name = $1' using term;
end;
$$;

-- Tingkat C (semantik): definer melewati RLS tanpa memeriksa kepemilikan pesanan.
-- @lab vuln business-idor cwe=CWE-639 tier=C in_scope=false lines=8 :: cancel_order tidak memeriksa pemilik
create function public.cancel_order(order_id bigint)
returns void
language sql
security definer
set search_path = ''
as $$
  update public.orders set status = 'cancelled' where id = order_id
$$;

-- @lab vuln view-no-invoker cwe=CWE-284 tier=A lines=4 :: view berjalan dengan hak pemilik, melewati RLS
create view public.user_stats as
  select user_id, count(*) as todo_count
  from public.todos
  group by user_id;

-- @lab decoy view-no-invoker cwe=CWE-284 lines=4 :: security_invoker aktif
create view public.my_todo_stats with (security_invoker = true) as
  select user_id, count(*) as todo_count
  from public.todos
  group by user_id;

-- @lab vuln grant-broad cwe=CWE-732 tier=A :: GRANT ALL ke anon
grant all on public.audit_log to anon;

-- @lab decoy grant-broad cwe=CWE-732 :: SELECT untuk authenticated
grant select on public.profiles to authenticated;

-- @lab vuln default-priv cwe=CWE-732 tier=A :: privilege bawaan terlalu longgar
alter default privileges in schema public grant all on tables to anon, authenticated;

-- @lab decoy default-priv cwe=CWE-732 :: hanya SELECT untuk authenticated
alter default privileges in schema public grant select on tables to authenticated;
