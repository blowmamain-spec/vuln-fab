<?php
class DatabaseSeeder
{
    public function run()
    {
        User::create(['email' => 'admin@example.com', 'password' => Hash::make('password')]);  // vuln: lv-seeder-password
    }
}
