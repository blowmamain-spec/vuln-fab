<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model  // vuln: lv-hidden-missing
{
    protected $fillable = ['title'];
}
