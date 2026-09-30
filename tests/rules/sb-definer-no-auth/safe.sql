create table public.profiles (id uuid primary key, nama text);
create function public.rename_me(p_nama text)
returns void language plpgsql security definer set search_path = ''
as $$ begin update public.profiles set nama = p_nama where id = (select auth.uid()); end $$;
create function public.touch() returns trigger language plpgsql security definer set search_path = ''
as $$ begin update public.profiles set nama = nama where id = new.id; return new; end $$;
create function public.count_profiles() returns bigint language sql security definer set search_path = ''
as $$ select count(*) from public.profiles $$;
create function public.invoker_update(p_id uuid) returns void language sql security invoker
as $$ update public.profiles set nama = 'x' where id = p_id $$;
create function public.admin_only(p_id uuid) returns void language plpgsql security definer set search_path = ''
as $$ begin if not is_admin() then raise exception 'no'; end if; delete from public.profiles where id = p_id; end $$;
