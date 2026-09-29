<?php

use App\Models\Post;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

class PostController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth')->only(['update']);
    }

    public function destroy($id)
    {
        $post = Post::where('user_id', Auth::id())->findOrFail($id);
        $post->delete();
    }

    public function update($id)
    {
        Post::findOrFail($id)->update(['seen' => true]);
    }

    public function index()
    {
        return Post::all();
    }
}

Route::middleware('auth:sanctum')->group(function () {
    Route::get('/secure/{id}', function ($id) {
        return Post::findOrFail($id);
    });
});
Route::delete('/posts/{id}', [PostController::class, 'destroy']);
Route::put('/posts/{id}', [PostController::class, 'update']);
Route::get('/posts', [PostController::class, 'index']);
Route::post('/login', function (Request $request) {
    Post::create(['x' => 1]);
});
