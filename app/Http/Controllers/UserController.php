<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Exception\AwsException;

class UserController extends Controller
{
    private $cognito;

    public function __construct()
    {
        $this->cognito = new CognitoIdentityProviderClient([
            'version' => 'latest',
            'region' => config('services.cognito.region'),
            'credentials' => [
                'key' => config('services.cognito.key'),
                'secret' => config('services.cognito.secret'),
            ],
        ]);
    }


    public function register(Request $request)
    {
        $this->validate($request, [
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required|min:8',
        ]);

        $username = $request->input('email');
        $password = $request->input('password');
        $name = $request->input('name');

        try {
            $result = $this->cognito->signUp([
                'ClientId' => config('services.cognito.client_id'),
                'Username' => $username,
                'Password' => $password,
                'UserAttributes' => [
                    ['Name' => 'email', 'Value' => $username],
                    ['Name' => 'name', 'Value' => $name],
                    // Add any other attributes as needed
                ],
            ]);

            return response()->json(['message' => 'User registered successfully.']);
        } catch (AwsException $e) {
            return response()->json(['message' => $e->getAwsErrorMessage()], 400);
        }
    }

    public function login(Request $request)
    {
        $username = $request->input('email');
        $password = $request->input('password');

        try {
            $result = $this->cognito->initiateAuth([
                'AuthFlow' => 'USER_PASSWORD_AUTH',
                'ClientId' => config('services.cognito.client_id'),
                'AuthParameters' => [
                    'USERNAME' => $username,
                    'PASSWORD' => $password,
                ],
            ]);

            // Get the tokens from the result and handle accordingly (e.g., store in session)
            $accessToken = $result->get('AuthenticationResult')['AccessToken'];
            $idToken = $result->get('AuthenticationResult')['IdToken'];

            return response()->json(['access_token' => $accessToken, 'id_token' => $idToken]);
        } catch (AwsException $e) {
            return response()->json(['message' => $e->getAwsErrorMessage()], 401);
        }
    }
}
