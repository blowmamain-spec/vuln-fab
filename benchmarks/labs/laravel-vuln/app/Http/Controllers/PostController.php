<?php

namespace App\Http\Controllers;

use App\Models\Country;
use App\Models\Post;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;

class PostController extends Controller
{
    public function search(Request $request)
    {
        $title = $request->input('title');
        // @lab vuln sqli cwe=CWE-89 tier=A :: input request digabung ke SQL
        return DB::select("select * from posts where title = '" . $title . "'");
    }

    public function searchSafe(Request $request)
    {
        $title = $request->input('title');
        // @lab decoy sqli cwe=CWE-89 :: query berparameter
        return DB::select('select * from posts where title = ?', [$title]);
    }

    public function convert(Request $request)
    {
        $file = $request->input('file');
        // @lab vuln cmd-injection cwe=CWE-78 tier=A :: input masuk ke shell
        exec('convert ' . $file . ' out.png');
    }

    public function convertSafe(Request $request)
    {
        $file = $request->input('file');
        // @lab decoy cmd-injection cwe=CWE-78 :: argumen di-escape
        exec('convert ' . escapeshellarg($file) . ' out.png');
    }

    public function read(Request $request)
    {
        $path = $request->input('path');
        // @lab vuln path-traversal cwe=CWE-22 tier=A :: path dari klien
        return Storage::get($path);
    }

    public function readSafe(Request $request)
    {
        $name = basename($request->input('path'));
        // @lab decoy path-traversal cwe=CWE-22 :: hanya nama dasar
        return Storage::get('public/' . $name);
    }

    public function proxy(Request $request)
    {
        $url = $request->input('url');
        // @lab vuln ssrf cwe=CWE-918 tier=A :: URL dari klien diminta server
        return Http::get($url)->body();
    }

    public function proxySafe(Request $request)
    {
        $city = $request->input('city');
        // @lab decoy ssrf cwe=CWE-918 :: host tetap
        return Http::get('https://api.example.com/weather', ['city' => $city])->body();
    }

    public function go(Request $request)
    {
        $next = $request->input('next');
        // @lab vuln redirect cwe=CWE-601 tier=A :: redirect ke URL dari klien
        return redirect($next);
    }

    public function goSafe(Request $request)
    {
        $next = $request->input('next');
        if (! in_array($next, ['/home', '/posts'])) {
            $next = '/home';
        }
        // @lab decoy redirect cwe=CWE-601 :: daftar putih
        return redirect($next);
    }

    public function restore(Request $request)
    {
        $state = $request->input('state');
        // @lab vuln deserialization cwe=CWE-502 tier=A :: unserialize atas data klien
        return unserialize($state);
    }

    public function greet(Request $request)
    {
        $name = $request->input('name');
        // @lab vuln xss cwe=CWE-79 tier=A :: input dicetak tanpa escape
        echo '<p>Hello ' . $name . '</p>';
    }

    public function greetSafe(Request $request)
    {
        $name = $request->input('name');
        // @lab decoy xss cwe=CWE-79 :: di-escape
        echo '<p>Hello ' . htmlspecialchars($name) . '</p>';
    }

    public function show($id)
    {
        // @lab vuln idor cwe=CWE-639 tier=B :: post diambil dari id URL tanpa cek pemilik
        $post = Post::find($id);
        return $post;
    }

    public function showMine(Request $request, $id)
    {
        // @lab decoy idor cwe=CWE-639 :: dibatasi ke pemilik
        $post = Post::where('user_id', $request->user()->id)->findOrFail($id);
        return $post;
    }

    public function country($id)
    {
        // @lab decoy idor cwe=CWE-639 :: data referensi bersama
        return Country::find($id);
    }

    public function store(Request $request)
    {
        // @lab vuln mass-assignment cwe=CWE-915 tier=A :: seluruh request masuk ke create()
        return Post::create($request->all());
    }

    public function storeSafe(Request $request)
    {
        $data = $request->validate(['title' => 'required', 'body' => 'required']);
        // @lab decoy mass-assignment cwe=CWE-915 :: hanya data tervalidasi
        return Post::create($data);
    }

    // @lab vuln route-no-auth cwe=CWE-306 tier=A :: menghapus data tanpa autentikasi
    public function destroy($id)
    {
        Post::where('id', $id)->delete();
    }

    // @lab decoy route-no-auth cwe=CWE-306 :: rute berada di grup auth
    public function destroyMine(Request $request, $id)
    {
        Post::where('id', $id)->where('user_id', $request->user()->id)->delete();
    }
}
