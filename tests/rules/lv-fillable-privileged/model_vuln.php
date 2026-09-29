<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model  // vuln: lv-fillable-privileged
{
    protected $fillable = ['title', 'is_admin'];
    protected $hidden = ['api_token'];
}
