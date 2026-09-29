create table public.t (id int, user_id uuid);
create view public.v1 as select * from public.t;  -- vuln: sb-view-no-invoker
create view public.v2 with (security_invoker = false) as select id from public.t;  -- vuln: sb-view-no-invoker
