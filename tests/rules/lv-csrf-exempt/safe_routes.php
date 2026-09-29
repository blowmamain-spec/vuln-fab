<?php

use App\Models\Order;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('/pay', function (Request $request) {
    Order::create(['paid' => true]);
});
