<?php

namespace App\Http\Middleware;

use App\Models\User;
use Closure;
use Illuminate\Support\Facades\Auth;

class CognitoMiddleware
{
    public function handle($request, Closure $next)
    {

        $bearerToken = $request->bearerToken();

        $tokenDetails = $this->decodeJWT($bearerToken);


        if (isset($tokenDetails->username)) {
            $getUser = User::query()->where('cognitoId', $tokenDetails->username)->first();

            if ($getUser) {
                return $next($request);
            }
            return response()->json(['message' => 'Unauthorized. Cognito authentication required.'], 401);
        };
        return response()->json(['message' => 'Unauthorized. Cognito authentication required.'], 401);
    }

    public function decodeJWT($token)
    {
        $tokenParts = explode(".", $token);
        $tokenHeader = base64_decode($tokenParts[0]);
        $tokenPayload = base64_decode($tokenParts[1]);
        $jwtHeader = json_decode($tokenHeader);
        $jwtPayload = json_decode($tokenPayload);

        return $jwtPayload;
    }
}
