<?php

namespace App\Http\Requests\User;

use App\Http\Requests\Request;

class UpdateUserRequest extends Request
{

    public function rules()
    {
        return [
            'name' => 'max:255',
            'email' => 'email|unique:users|max:255',
            'password' => 'min:6|max:255',
        ];
    }
}
