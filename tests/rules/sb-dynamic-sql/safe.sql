create function public.s1(term text) returns void language plpgsql set search_path = '' as $$
begin
  execute format('delete from public.t where name = %L', term);
end;
$$;

create function public.s2(term text) returns void language plpgsql set search_path = '' as $$
begin
  execute 'delete from public.t where name = $1' using term;
end;
$$;

create function public.s3(tbl text) returns void language plpgsql set search_path = '' as $$
begin
  execute 'truncate ' || quote_ident(tbl);
end;
$$;

create function public.s4() returns void language plpgsql set search_path = '' as $$
begin
  execute 'select 1';
end;
$$;

create function public.s5(x int) returns int language sql set search_path = '' as $$ select x $$;
