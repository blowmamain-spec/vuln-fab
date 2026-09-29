-- @lab vuln seed-secret cwe=CWE-798 tier=A lines=2 :: akun admin dengan password hardcoded
insert into auth.users (id, email, encrypted_password, email_confirmed_at)
values ('00000000-0000-0000-0000-000000000001', 'admin@example.com', crypt('admin123', gen_salt('bf')), now());

-- @lab decoy seed-secret cwe=CWE-798 lines=2 :: password dari pengaturan runtime
insert into auth.users (id, email, encrypted_password, email_confirmed_at)
values ('00000000-0000-0000-0000-000000000002', 'demo@example.com', crypt(current_setting('app.seed_password', true), gen_salt('bf')), now());

-- @lab decoy seed-secret cwe=CWE-798 lines=2 :: data biasa
insert into public.todos (user_id, title)
values ('00000000-0000-0000-0000-000000000002', 'Try the demo');
