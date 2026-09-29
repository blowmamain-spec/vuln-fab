create table public.t (id int);
grant select on public.t to anon;
grant select, insert on public.t to authenticated;
grant all on public.t to service_role;
create table public.revoked (id int);
grant all on public.revoked to anon;
revoke all on public.revoked from anon;
create table private.hidden (id int);
grant all on private.hidden to anon;
