<?php

namespace App\Http\Middleware;

class VerifyCsrfToken
{
    // @lab decoy csrf-wildcard cwe=CWE-352 :: hanya webhook yang dikecualikan
    protected $except = ['webhook/*'];
}
