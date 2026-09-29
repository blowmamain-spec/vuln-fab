<?php

return [
    'name' => env('APP_NAME', 'Lab'),
    // @lab decoy app-debug cwe=CWE-489 :: dibaca dari environment
    'debug' => (bool) env('APP_DEBUG', false),
];
