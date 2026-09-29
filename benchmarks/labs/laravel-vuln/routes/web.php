<?php

use App\Http\Controllers\PostController;
use Illuminate\Support\Facades\Route;

Route::get('/search', [PostController::class, 'search']);
Route::get('/search-safe', [PostController::class, 'searchSafe']);
Route::get('/convert', [PostController::class, 'convert']);
Route::get('/convert-safe', [PostController::class, 'convertSafe']);
Route::get('/read', [PostController::class, 'read']);
Route::get('/read-safe', [PostController::class, 'readSafe']);
Route::get('/proxy', [PostController::class, 'proxy']);
Route::get('/proxy-safe', [PostController::class, 'proxySafe']);
Route::get('/go', [PostController::class, 'go']);
Route::get('/go-safe', [PostController::class, 'goSafe']);
Route::post('/restore', [PostController::class, 'restore']);
Route::get('/greet', [PostController::class, 'greet']);
Route::get('/greet-safe', [PostController::class, 'greetSafe']);

Route::middleware('auth')->group(function () {
    Route::get('/posts/{id}', [PostController::class, 'show']);
    Route::get('/mine/{id}', [PostController::class, 'showMine']);
    Route::get('/countries/{id}', [PostController::class, 'country']);
    Route::post('/posts', [PostController::class, 'store']);
    Route::post('/posts-safe', [PostController::class, 'storeSafe']);
    Route::delete('/mine/{id}', [PostController::class, 'destroyMine']);
});

Route::delete('/posts/{id}', [PostController::class, 'destroy']);

// @lab vuln route-no-auth cwe=CWE-306 tier=A :: webhook mengubah data tanpa verifikasi pemanggil
// @lab vuln csrf-exempt cwe=CWE-352 tier=A :: dikecualikan dari CSRF lewat VerifyCsrfToken::$except
Route::post('/webhook/pay', function () {
    Post::create(['title' => 'paid']);
});
