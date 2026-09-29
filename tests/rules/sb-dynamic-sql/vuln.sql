create function public.f1(term text) returns void language plpgsql set search_path = '' as $$
begin
  execute 'delete from public.t where name = ''' || term || '''';  -- vuln: sb-dynamic-sql
end;
$$;

create function public.f2(col text) returns setof public.t language plpgsql set search_path = '' as $$
begin
  return query execute format('select * from public.t where name = %s', col);  -- vuln: sb-dynamic-sql
end;
$$;

create function public.f3(a text, b text) returns void language plpgsql set search_path = '' as $$
declare
  q text;
begin
  execute 'update public.t set ' || a || ' = ' || quote_literal(b);  -- vuln: sb-dynamic-sql
end;
$$;
