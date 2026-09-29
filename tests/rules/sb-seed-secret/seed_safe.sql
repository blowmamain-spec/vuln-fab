insert into auth.users (id, email, encrypted_password)
values ('1', 'a@example.com', crypt(current_setting('app.seed_password', true), gen_salt('bf')));
insert into public.todos (user_id, title) values ('1', 'hello');
create role app_reader nologin;
insert into public.profiles (id, password_hint) values ('1', 'a hint column that is not a password');
