<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Exception\AwsException;
use Illuminate\Auth\Events\Registered;
use Illuminate\Validation\ValidationException;
use App\Http\Controllers\Validators\Validator;
use Illuminate\Support\Facades\Validator as FacadesValidator;
use App\Cognito\CognitoClient;
use Illuminate\Http\JsonResponse;

class LoginController extends Controller
{

    protected $cognito;

    public function __construct(CognitoClient $cognito)
    {
        $this->cognito = $cognito;
    }

    public function login(Request $request)
    {
        $username = $request->input('email');
        $password = $request->input('password');

        try {
            // Use the new method to initiate authentication with USER_PASSWORD_AUTH flow.
            $result = $this->cognito->initiateAuth('ADMIN_NO_SRP_AUTH', $username, $password);

            if (!$result) {
                // Authentication failed
                return response()->json(['message' => 'Authentication failed.'], 401);
            }

            // Get the tokens from the result
            $accessToken = $result->get('AuthenticationResult')['AccessToken'];
            $idToken = $result->get('AuthenticationResult')['IdToken'];

            // Retrieve the user from your local user table
            $user = User::where('email', $username)->first();

            return response()->json([
                'message' => 'Login successful.',
                'access_token' => $accessToken,
                'id_token' => $idToken,
                'user' => $user,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return response()->json(['message' => $e->getAwsErrorMessage()], 401);
        }
    }

    public function loginv(Request $request)
    {
        try {
            $request->validate([
                'email' => 'required|string|email',
                'password' => 'required|string',
            ]);

            $email = $request->input('email');
            $password = $request->input('password');

            // Use the CognitoClient to attempt authentication
            $result = app()->make(CognitoClient::class)->login($email, $password);
            if ($result) {
                // Authentication successful
                return response()->json(['message' => 'Login successful'], 200);
            } else {
                // Authentication failed
                throw ValidationException::withMessages(['email' => 'Invalid credentials']);
            }
        } catch (\Exception $e) {
            // Handle exceptions
            return response()->json(['error' => $e->getMessage()], 401);
        }
    }
    public function register(Request $request)
    {
        try {
            $request->validate([
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users',
                'password' => 'required|string|min:8|confirmed',
            ]);

            $attributes = [];

            $userFields = ['name', 'email'];

            foreach ($userFields as $userField) {
                if ($request->$userField === null) {
                    throw new \Exception("The configured user field $userField is not provided in the request.");
                }
                $attributes[$userField] = $request->$userField;
            }

            app()->make(CognitoClient::class)->register($request->email, $request->password, $attributes);

            event(new Registered($user = $this->create($request->all())));

            return response()->json(['message' => 'Registration successful'], 201);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 400);
        }
    }
    protected function create(array $data)
    {
        return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password']),
        ]);
    }
}
