<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;

// @lab decoy hidden-missing cwe=CWE-200 :: password dan token disembunyikan
class User extends Authenticatable
{
    // @lab vuln fillable-privileged cwe=CWE-915 tier=A :: is_admin bisa diisi massal
    protected $fillable = ['email', 'password', 'is_admin'];

    protected $hidden = ['password', 'remember_token'];
}
