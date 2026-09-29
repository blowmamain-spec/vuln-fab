create table public.t (id int);
create table public.u (id int);
grant all on public.t to anon;  -- vuln: sb-grant-broad
grant insert, update on public.u to public;  -- vuln: sb-grant-broad
grant all on public.u to authenticated;  -- vuln: sb-grant-broad
