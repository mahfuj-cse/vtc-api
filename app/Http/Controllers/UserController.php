<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Auth\CognitoClient;

class UserController extends Controller
{
    private $cognitoClient;

    public function __construct(CognitoClient $cognitoClient)
    {
        $this->cognitoClient = $cognitoClient;
    }

    public function authenticate(Request $request)
    {
        $username = $request->input('username');
        $password = $request->input('password');

        try {
            // Authenticate user
            $this->cognitoClient->authenticate($username, $password);

            $result = $this->cognitoClient->result; // Update this line based on your actual property name

            if ($result->login_successful) {
                // Authentication successful
                return response()->json(['message' => 'Authentication successful']);
            } elseif ($result->new_password_required) {
                // User needs to reset password
                return response()->json(['message' => 'New password required']);
            } else {
                // Authentication unsuccessful
                return response()->json(['message' => 'Authentication failed'], 401);
            }
        } catch (\Exception $e) {
            // Handle exceptions
            return response()->json(['message' => $e->getMessage()], 500);
        }
    }
    public function listUsers()
    {
        // Example endpoint for listing users
        try {
            $this->cognitoClient->listUsers();

            $result = $this->cognitoClient->result; // Update this line based on your actual property name

            if ($result->result) {
                // Users listed successfully
                return response()->json(['users' => $result->response]);
            } else {
                // Failed to list users
                return response()->json(['message' => 'Failed to list users'], 500);
            }
        } catch (\Exception $e) {
            // Handle exceptions
            return response()->json(['message' => $e->getMessage()], 500);
        }
    }


    public function createUser(Request $request)
    {
        // Example endpoint for user creation

        $username = $request->input('username');
        $temporaryPassword = $request->input('temporary_password');

        try {
            // Create user
            $result = $this->cognitoClient->createUser([
                'Username' => $username,
                'TemporaryPassword' => $temporaryPassword,
            ]);

            if ($result) {
                // User created successfully
                return response()->json(['message' => 'User created successfully']);
            } else {
                // Failed to create user
                return response()->json(['message' => 'Failed to create user'], 500);
            }
        } catch (\Exception $e) {
            // Handle exceptions
            return response()->json(['message' => $e->getMessage()], 500);
        }
    }

    public function updateUserAttributes(Request $request, $username)
    {
        // Example endpoint for updating user attributes
        $attributes = $request->input('attributes');

        try {
            // Update user attributes
            $result = $this->cognitoClient->updateUserAttributes($username, $attributes);

            if ($result) {
                // User attributes updated successfully
                return response()->json(['message' => 'User attributes updated successfully']);
            } else {
                // Failed to update user attributes
                return response()->json(['message' => 'Failed to update user attributes'], 500);
            }
        } catch (\Exception $e) {
            // Handle exceptions
            return response()->json(['message' => $e->getMessage()], 500);
        }
    }


    public function signUp(Request $request)
    {
        // Example endpoint for user signup

        $username = $request->input('username');
        $password = $request->input('password');
        $attributes = $request->input('attributes', []); // Additional user attributes

        try {
            // Sign up user
            $result = $this->cognitoClient->signUp($username, $password, $attributes);

            if ($result) {
                // User signed up successfully
                return response()->json(['message' => 'User signed up successfully']);
            } else {
                // Failed to sign up user
                return response()->json(['message' => 'Failed to sign up user'], 500);
            }
        } catch (\Exception $e) {
            // Handle exceptions
            return response()->json(['message' => $e->getMessage()], 500);
        }
    }

    public function getUserByEmail(Request $request)
    {
        $email = $request->input('email'); // Get email from the request

        try {
            if ($this->cognitoClient->getUser($email)) {
                $user = $this->cognitoClient->payload; // Access the 'payload' property directly

                // Do something with the user data, for example, return it as JSON
                return response()->json(['user' => $user]);
            } else {
                // Handle the case where fetching user data failed
                return response()->json(['message' => 'Failed to get user data'], 500);
            }
        } catch (\Exception $e) {
            // Handle exceptions
            return response()->json(['message' => $e->getMessage()], 500);
        }
    }

    // Add more methods as needed for your use case
}
