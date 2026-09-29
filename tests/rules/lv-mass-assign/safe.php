<?php

class UserController
{
    public function store(Request $request)
    {
        $data = $request->validate(['name' => 'required']);
        return User::create($data);
    }

    public function update(Request $request, User $user)
    {
        $user->update($request->only(['name', 'email']));
        $user->fill($request->validated());
    }

    public function scalar(Request $request)
    {
        return User::create(['name' => $request->input('name')]);
    }
}
