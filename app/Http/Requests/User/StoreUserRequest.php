<?php

namespace App\Http\Requests\User;

use App\Http\Requests\Request;

class StoreUserRequest extends Request
{

    public function rules()
    {
        return [
            'name' => 'max:255',
            'email' => 'email|required|unique:users|max:255',
            'password' => 'required|min:6|max:255',
        ];
    }
}
