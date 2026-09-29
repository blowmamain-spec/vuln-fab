create table public.t (id int, user_id uuid);
create view public.v1 with (security_invoker = true) as select * from public.t;
create view public.v2 with (security_invoker = on) as select id from public.t;
create schema private;
create view private.v3 as select * from public.t;
create view public.dropped as select 1;
drop view public.dropped;
