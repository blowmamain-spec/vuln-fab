<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

// @lab vuln hidden-missing cwe=CWE-200 tier=A :: api_token tidak disembunyikan dari JSON
class Post extends Model
{
    // @lab vuln guarded-empty cwe=CWE-915 tier=A :: semua kolom bisa diisi massal
    protected $guarded = [];
}
