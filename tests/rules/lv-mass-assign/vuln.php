<?php

class UserController
{
    public function store(Request $request)
    {
        return User::create($request->all());  // vuln: lv-mass-assign
    }

    public function update(Request $request, User $user)
    {
        $data = $request->except(['_token']);
        $user->update($data);  // vuln: lv-mass-assign
    }
}
