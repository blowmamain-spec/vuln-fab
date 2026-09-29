create table public.a (id bigint primary key);
alter table public.a enable row level security;

create table public.enabled_later (id bigint primary key);
alter table public.enabled_later enable row level security;

create schema private;
create table private.internal (id bigint primary key);

create table public.forced (id bigint primary key);
alter table public.forced enable row level security, force row level security;

create temp table scratch (id int);
