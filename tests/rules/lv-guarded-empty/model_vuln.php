<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    protected $guarded = [];  // vuln: lv-guarded-empty
    protected $hidden = ['api_token'];
}
