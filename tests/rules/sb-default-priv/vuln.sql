alter default privileges in schema public grant all on tables to anon, authenticated;  -- vuln: sb-default-priv
alter default privileges for role postgres grant insert, update, delete on tables to anon;  -- vuln: sb-default-priv
