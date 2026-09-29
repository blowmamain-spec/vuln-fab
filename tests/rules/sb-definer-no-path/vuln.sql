create function public.get_secret(uid uuid)  -- vuln: sb-definer-no-path
returns text
language sql
security definer
as $$ select 'x' $$;

create function public.later() returns int language sql as $$ select 1 $$;  -- vuln: sb-definer-no-path
alter function public.later() security definer;
