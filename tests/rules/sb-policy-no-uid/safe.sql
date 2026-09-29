create table public.projects (id int, user_id uuid, is_public boolean);
alter table public.projects enable row level security;
create policy "owner" on public.projects for select to authenticated using ((select auth.uid()) = user_id);
create policy "pub_or_owner" on public.projects for select to authenticated using (is_public or auth.uid() = user_id);
create policy "helper" on public.projects for select to authenticated using (is_member(id));
create policy "all_open" on public.projects for select using (true);

create table public.posts (id int, author_id uuid, is_public boolean);
alter table public.posts enable row level security;
create policy "pub" on public.posts for select using (is_public);
