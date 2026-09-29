<?php

use App\Models\Post;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

class PostController extends Controller
{
    public function destroy($id)  // vuln: lv-route-no-auth
    {
        Post::findOrFail($id)->delete();
    }

    public function show($id)  // vuln: lv-route-no-auth
    {
        return Post::findOrFail($id);
    }
}

Route::delete('/posts/{id}', [PostController::class, 'destroy']);
Route::get('/posts/{id}', 'PostController@show');
Route::post('/posts', function (Request $request) {  // vuln: lv-route-no-auth
    Post::create(['title' => $request->title]);
});
