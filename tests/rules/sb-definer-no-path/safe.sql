create function public.a() returns int language sql security definer set search_path = '' as $$ select 1 $$;
create function public.b() returns int language sql security definer set search_path = public, extensions as $$ select 1 $$;
create function public.c() returns int language sql security invoker as $$ select 1 $$;
create function public.d() returns int language sql as $$ select 1 $$;
create function public.e() returns int language sql security definer as $$ select 1 $$;
alter function public.e() set search_path = '';
