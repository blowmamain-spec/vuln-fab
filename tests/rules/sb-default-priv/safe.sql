alter default privileges in schema public grant select on tables to authenticated;
alter default privileges in schema public grant all on tables to service_role;
alter default privileges in schema public revoke all on tables from anon;
alter default privileges in schema private grant all on tables to anon;
alter default privileges in schema public grant execute on functions to authenticated;
