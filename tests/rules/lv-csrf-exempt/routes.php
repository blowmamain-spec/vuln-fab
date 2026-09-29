<?php

use App\Models\Order;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Middleware\VerifyCsrfToken;

Route::post('/pay', function (Request $request) {  // vuln: lv-csrf-exempt
    Order::create(['paid' => true]);
})->withoutMiddleware([VerifyCsrfToken::class]);
