<?php
namespace App\Http\Middleware;

class VerifyCsrfToken
{
    protected $except = ['*'];  // vuln: lv-csrf-wildcard
}
