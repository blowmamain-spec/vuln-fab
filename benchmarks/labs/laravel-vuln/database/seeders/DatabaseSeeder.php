<?php

namespace Database\Seeders;

class DatabaseSeeder
{
    public function run(): void
    {
        // @lab vuln seeder-password cwe=CWE-798 tier=A :: admin dengan kata sandi bawaan
        User::create(['email' => 'admin@example.com', 'password' => Hash::make('password')]);

        // @lab decoy seeder-password cwe=CWE-798 :: kata sandi dari environment
        User::create(['email' => 'ops@example.com', 'password' => Hash::make(env('OPS_PASSWORD'))]);
    }
}
