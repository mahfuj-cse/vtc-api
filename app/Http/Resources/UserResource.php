<?php

namespace App\Http\Resources;

class UserResource extends Resource
{
    public function toArray($request)
    {
        return [
            'id' => $this->id,
            'email' => $this->email,
        ];
    }
}
