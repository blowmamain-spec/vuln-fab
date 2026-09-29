<?php
class DatabaseSeeder
{
    public function run()
    {
        User::create(['email' => 'admin@example.com', 'password' => Hash::make(env('ADMIN_PASSWORD'))]);
    }
}
