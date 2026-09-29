insert into auth.users (id, email, encrypted_password)  -- vuln: sb-seed-secret
values ('1', 'a@example.com', crypt('admin123', gen_salt('bf')));

insert into auth.users (id, email, encrypted_password) values ('2', 'b@example.com', '$2a$10$abcdef');  -- vuln: sb-seed-secret

create role app_user login password 'hunter2';  -- vuln: sb-seed-secret
