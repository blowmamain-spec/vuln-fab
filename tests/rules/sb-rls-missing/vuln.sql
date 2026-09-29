create table public.notes (  -- vuln: sb-rls-missing
  id bigint primary key,
  body text
);

create table public.tasks (id bigint primary key);
alter table public.tasks enable row level security;
alter table public.tasks disable row level security;  -- vuln: sb-rls-missing

create table public.reset (id bigint primary key);
alter table public.reset enable row level security;
drop table public.reset;
create table public.reset (id bigint primary key);  -- vuln: sb-rls-missing
