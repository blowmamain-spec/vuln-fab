create table public.profiles (id uuid primary key, nama text);
create function public.rename_user(p_user_id uuid, p_nama text) -- vuln: sb-definer-no-auth
returns void language plpgsql security definer set search_path = ''
as $$ begin update public.profiles set nama = p_nama where id = p_user_id; end $$;
create function public.wipe(p_id uuid) -- vuln: sb-definer-no-auth
returns void language sql security definer set search_path = ''
as $$ delete from public.profiles where id = p_id $$;
