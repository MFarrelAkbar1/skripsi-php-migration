<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function store(Request $request)
    {
        $user = User::create($request->all());

        return view('profile', ['user' => $user]);
    }

    public function search(Request $request)
    {
        $name = $request->input('name');

        return DB::select("SELECT * FROM users WHERE name = '" . $name . "'");
    }

    public function adults()
    {
        return User::where('age', '>', 17)->get();
    }

    public function key()
    {
        return env('APP_KEY');
    }

    public function broken()
    {
        return strlen($undefinedVariable);
    }

    public function wrongType()
    {
        return $this->needsRequest('not a request');
    }

    private function needsRequest(Request $request)
    {
        return $request;
    }
}
