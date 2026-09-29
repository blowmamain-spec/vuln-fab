<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Country extends Model
{
    // @lab decoy guarded-empty cwe=CWE-915 :: daftar fillable eksplisit
    protected $fillable = ['name'];
}
