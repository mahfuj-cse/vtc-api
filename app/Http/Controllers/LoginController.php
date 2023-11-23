<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Ellaisys\Cognito\Auth\AuthenticatesUsers as CognitoAuthenticatesUsers;
use Ellaisys\Cognito\Auth\RegistersUsers;

use Illuminate\Http\JsonResponse;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

use Ellaisys\Cognito\AwsCognitoClient;
use Ellaisys\Cognito\AwsCognitoUserPool;

use Exception;
use Illuminate\Validation\ValidationException;
use Ellaisys\Cognito\Exceptions\InvalidUserFieldException;
use Ellaisys\Cognito\Exceptions\AwsCognitoException;
use Symfony\Component\HttpKernel\Exception\HttpException;

class LoginController extends Controller
{
    use CognitoAuthenticatesUsers, RegistersUsers;

    /**
     * Authenticate User
     *
     * @throws \HttpException
     *
     * @return mixed
     */
    public function login(Request $request)
    {
        // Implement your login logic here
        // Example: Authenticate user using AWS Cognito

        // Convert request to collection
        $collection = collect($request->all());

        // Authenticate with Cognito Package Trait (with 'api' as the auth guard)
        if ($response = $this->attemptLogin($collection, 'api', 'email', 'password', true)) {
            if (is_string($response)) {
                // If authentication is successful, $response contains the AWS Cognito access token

                // You can use this access token for further API requests or for authentication
                return response()->json(['status' => 'success', 'access_token' => $response]);
            } else {
                return response()->json(['status' => 'error', 'message' => $response], 400);
            }
        }
    }

    /**
     * Register a new user
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        // Implement your registration logic here
        // Example: Register user using AWS Cognito

        $validator = $request->validate([
            'name' => 'required|max:255',
            'email' => 'required|email|max:64|unique:users',
            'password' => 'sometimes|confirmed|min:6|max:64',
        ]);

        // Create credentials object
        $collection = collect($request->all());
        $data = $collection->only('name', 'email', 'password'); // Passing 'password' is optional.

        // Register User in Cognito
        if ($cognitoRegistered = $this->createCognitoUser($data)) {

            // If successful, create the user in the local database
            User::create($collection->only('name', 'email'));

            return response()->json(['status' => 'success', 'message' => 'Registration successful']);
        }

        return response()->json(['status' => 'error', 'message' => 'Registration failed'], 400);
    }

    
}
