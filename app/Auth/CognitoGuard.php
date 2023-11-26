<?php

namespace App\Auth;

use View;
use App\Auth\CognitoClient;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Session\Session;
use Symfony\Component\HttpFoundation\Request;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Support\Facades\Auth;

class CognitoGuard extends SessionGuard implements StatefulGuard
{
    public $client;

    public function __construct(
        string $name,
        CognitoClient $client,
        UserProvider $provider,
        Session $session,
        ?Request $request = null,
        $hasher
    ) {
        $this->client = $client;
        $this->hasher = $hasher;

        parent::__construct($name, $provider, $session, $request);

        $this->result = $client->result;
    }

    public function attempt(array $credentials = [], $remember = false)
    {
        $verify_creds = ['email' => $credentials['email']];
        $this->fireAttemptEvent($credentials, $remember);

        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($verify_creds);

        if ($user instanceof Authenticatable) {
            $verify_creds['password'] = $credentials['password'];
            if ($this->hasValidCredentials($user, $verify_creds)) {
                $this->result = $this->client->result;
                if ($this->client->result->new_password_required === true) {
                    return false;
                }

                $this->login($user, $remember);

                return true;
            } else {
                $this->result = $this->client->result;

                return false;
            }
        }

        $this->client->result = false;
        $this->result->login_unsuccessful = true;
        $this->result->message = 'User account not found';

        $this->fireFailedEvent($user, $credentials);

        return false;
    }

    public function adminGetUser($email)
    {
        if ($this->client->GetUser($email))

            return $this->client->payload;
    }

    public function adminListUsers()
    {
        if ($this->client->listUsers())
            return $this->client->result->response;

        return [];
    }

    public function adminUpdateUserAttributes($username, $attributes)
    {
        return $this->client->updateUserAttributes($username, $attributes);
    }

    public function adminCreateUser($email, $password)
    {
        return $this->client->createUser(['Username' => $email, 'TemporaryPassword' => $password]);
    }

    public function adminEnableUser($email)
    {
        return $this->client->enableUser($email);
    }

    public function adminDisableUser($email)
    {
        return $this->client->disableUser($email);
    }

    public function adminRemoveUser($username)
    {
        return $this->client->deleteCognitoUser($username);
    }

    public function adminResetPassword($username, $password)
    {
        return $this->client->resetUserPassword($username, $password);
    }

    public function updateForcePassword($session, $username, $password)
    {
        return $this->client->updateForcePassword($session, $username, $password);
    }

    public function check($request = null)
    {
        $token = $request->bearerToken(); // Assuming token is passed in the Authorization header

        if (!$token) {
            // Token not present, user not authenticated
            return false;
        }

        // Attempt to authenticate the user based on the token
        $user = $this->provider->retrieveByToken(null, $token);

        if ($user) {
            // Auth:setUser($user);
            $guard = Auth::guard('cognito'); // Use your guard name
            $guard->setUser($user);
            return true;
        }

        return false;
    }


    public function checkPassword($email, $password)
    {
        return $this->client->validatePassword($email, $password);
    }



    protected function hasValidCredentials($user, $credentials)
    {
        return $this->client->authenticate($credentials['email'], $credentials['password']);
    }

    protected function userFromRecaller($recaller)
    {
        if (!$recaller->valid() || $this->recallAttempted) {
            return;
        }

        $this->recallAttempted = true;
        $this->viaRemember = !is_null($user = $this->provider->retrieveByToken($recaller->id(), $recaller->token()));

        return $user;
    }
}
