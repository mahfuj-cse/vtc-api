<?php

namespace App\Auth;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentity\CognitoIdentityClient;

class CognitoClient
{
	const REFRESH_TOKEN_AUTH                = 'REFRESH_TOKEN_AUTH';
	const USER_PASSWORD_AUTH 				= 'USER_PASSWORD_AUTH';
	const RESPONSE_NEW_PASSWORD_REQUIRED	= 'NEW_PASSWORD_REQUIRED';

	protected $poolId;
	protected $appSecret;
	protected $clientId;

	public $client;
	public $IdentityClient;
	public $AccessToken;
	public $IdToken;
	public $RefreshToken;
	public $region;
	public $identityPoolId;
	public $version;
	public $account;
	public $config;
	public $error_message = '';
	public $error_code = '';

	public $payload;
	public $result;

	public function __construct(CognitoIdentityProviderClient $client, $clientId, $poolId, $appSecret, $region, $identityPoolId, $version, $credentials, $account, $config)
	{
		$this->client 	      = $client;
		$this->clientId       = $clientId;
		$this->poolId 	      = $poolId;
		$this->appSecret      = $appSecret;
		$this->region         = $region;
		$this->identityPoolId = $identityPoolId;
		$this->credentials    = $credentials;
		$this->version        = $version;
		$this->account        = $account;
		$this->config         = $config;
		$this->init_result();
		$this->IdentityClient = new CognitoIdentityClient([
			'version'     => $this->version,
			'region'      => $this->region,
			'credentials' => $this->credentials
		]);
		$this->init_result();
	}

	private function init_result()
	{
		$this->result = new \stdClass();
		$this->result->result = false;
		$this->result->response = [];
		$this->result->message = '';
		$this->result->new_password_required = false;
		$this->result->login_successful = false;
		$this->result->login_unsuccessful = false;
	}

	public function authenticate($username, $password)
	{
		$auth_parameters = ['USERNAME'	=> $username, 'PASSWORD' => $password];
		if (!empty($this->appSecret))
			$auth_parameters['SECRET_HASH'] = $this->hash($username . $this->clientId);
// dd($this->result);
		try {
			$this->init_result();
			$result = $this->client->InitiateAuth([
				'AuthFlow' 		 => self::USER_PASSWORD_AUTH,
				'ClientId' 		 => $this->clientId,
				'UserPoolId'	 => $this->poolId,
				'AuthParameters' => $auth_parameters
			]);
// dd($result);
			$this->result->result = true;
			$this->result->response = $result;

			if ($result->get('ChallengeName') == self::RESPONSE_NEW_PASSWORD_REQUIRED)
				$this->result->new_password_required = true;

			if ($result->get('ChallengeName') == self::RESPONSE_NEW_PASSWORD_REQUIRED) {
				session([
					'CognitoNeedsReset'  => true,
					'CognitoSession'	 => $result->get('Session'),
					'CognitoUsername' 	 => $username
				]);

				return true;
			}

			$this->AccessToken 	= $result->get('AuthenticationResult')['AccessToken'];
			$this->IdToken 		= $result->get('AuthenticationResult')['IdToken'];
			$this->RefreshToken	= $result->get('AuthenticationResult')['RefreshToken'];

			session([
				'CognitoAccessToken'	=> $this->AccessToken,
				'CognitoIdToken'		=> $this->IdToken,
				'CognitoRefreshToken'	=> $this->RefreshToken,
				'CognitoUsername'       => $username,
				'CognitoExpiry'         => time() + ($result->get('AuthenticationResult')['ExpiresIn'] * 1)
			]);

			$this->result->login_successful = true;
			return response()->json([
				'token' => $this->AccessToken, // Include the access token in the response
				'message' => 'Authentication successful'
			]);

			return true;
		} catch (\Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e) {

			$this->error_message = $e->getAwsErrorMessage();
			$this->error_code    = $e->getAwsErrorCode();

			$this->result->response = $e;
			$this->result->login_unsuccessful = true;
			$this->result->message = $e->getAwsErrorMessage();
		}

		return false;
	}

	public function validatePassword($username, $password)
	{
		$auth_parameters = ['USERNAME'	=> $username, 'PASSWORD' => $password];
		if (!empty($this->appSecret))
			$auth_parameters['SECRET_HASH'] = $this->hash($username . $this->clientId);

		try {
			$this->init_result();
			$result = $this->client->InitiateAuth([
				'AuthFlow' 		 => self::USER_PASSWORD_AUTH,
				'ClientId' 		 => $this->clientId,
				'UserPoolId'	 => $this->poolId,
				'AuthParameters' => $auth_parameters
			]);

			return true;
		} catch (\Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e) {

			$this->error_message = $e->getAwsErrorMessage();
			$this->error_code    = $e->getAwsErrorCode();

			$this->result->response = $e;
			$this->result->login_unsuccessful = true;
			$this->result->message = $e->getAwsErrorMessage();
		}

		return false;
	}

	public function listUsers()
	{

		try {


			$result = $this->client->ListUsers(['UserPoolId' => $this->poolId]);


			$this->result->result = true;
			$this->result->response = $result->get('Users');

			return true;
		}catch (\Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e) {

			$this->error_message = $e->getAwsErrorMessage();
			$this->error_code    = $e->getAwsErrorCode();
		
			// Log or return the exception details for debugging
			\Log::error('Cognito ListUsers Exception', [
				'error_message' => $this->error_message,
				'error_code'    => $this->error_code,
				'exception'     => $e
			]);
		
			$this->result->result = false;
			$this->result->message = $this->error_message;
		
			return false;
		}
	}

	public function adminConfirmSignUp($username)
	{
		try {
			$result = $this->client->adminConfirmSignUp([
				'UserPoolId' => $this->poolId,
				'Username'   => $username,
			]);

			// Check if the confirmation was successful
			if ($result->get('UserConfirmed')) {
				// User is confirmed, you can proceed with additional actions if needed
				// For example, update your local user record or log the user in.
				return true;
			} else {
				// User is not confirmed. You may need to handle the confirmation process.
				// This usually involves sending a confirmation code to the user's email.
				// The confirmation code is required to confirm the user's registration.
				// You can use $result->get('UserSub') to get the user's unique identifier.
				// Send the confirmation code to the user through your preferred method (email, SMS, etc.).
				return false;
			}
		} catch (\Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e) {
			// Handle the exception, log it, and provide feedback to the user
			$errorMessage = $e->getAwsErrorMessage();
			$errorCode = $e->getAwsErrorCode();

			// You may want to throw an exception or return an error response
			// depending on your application's logic.
			// Consider checking for specific error codes to handle different scenarios.
			return false;
		}
	}


	public function signUp($username, $password, $attributes = [])
	{
		$userAttributes = [];

		foreach ($attributes as $name => $value) {
			$userAttributes[] = [
				'Name'  => $name,
				'Value' => $value,
			];
		}

		$signUpParams = [
			'ClientId'       => $this->clientId,
			'Username'       => $username,
			'Password'       => $password,
			'UserAttributes' => $userAttributes,
		];

		if (!empty($this->appSecret)) {
			$signUpParams['SecretHash'] = $this->hash($username . $this->clientId);
		}

		try {
			// dd($signUpParams);

			$result = $this->client->signUp($signUpParams);
			// $ct = $this->client->adminConfirmSignUp($username);
             
			// $username = $username; // Replace with the actual username
			if ($this->client->adminConfirmSignUp($username)) {
				// User sign-up confirmed successfully
				return response()->json(['message' => 'User sign-up confirmed successfully']);
			} else {
				// Failed to confirm user sign-up
				return response()->json(['message' => 'Failed to confirm user sign-up'], 500);
			}


			// Check if the user needs to confirm the registration
			if ($result->get('UserConfirmed')) {
				// User is confirmed, you can proceed with additional actions if needed
				// For example, send a confirmation email, etc.
				// The user is not signed in automatically after signup. They usually need to confirm their email.
				return true;
			} else {
				// User is not confirmed. You may need to handle the confirmation process.
				// This usually involves sending a confirmation code to the user's email.
				// The confirmation code is required to confirm the user's registration.
				// You can use $result->get('UserSub') to get the user's unique identifier.
				// Send the confirmation code to the user through your preferred method (email, SMS, etc.).
				return false;
			}
		} catch (\Aws\Exception\AwsException $e) {
			// Handle the exception, log it, and provide feedback to the user
			$errorMessage = $e->getAwsErrorMessage();
			$errorCode = $e->getAwsErrorCode();

			// You may want to throw an exception or return an error response
			// depending on your application's logic.
			// Consider checking for specific error codes to handle different scenarios.
			return false;
		}
	}


	public function createUser($details = array())
	{
		//   @todo 'DesiredDeliveryMediums'=> ['EMAIL'], ... , MessageAction use EMAIL instead of SUPPRESS to send
		$options = [
			'MessageAction'  	    => 'SUPPRESS', //'EMAIL'
			'Username' 		    	=> $details['Username'],
			'TemporaryPassword' 	=> $details['TemporaryPassword'],
			'UserPoolId' 			=> $this->poolId
		];

		try {
			$result         = $this->client->adminCreateUser($options);
			dd($result);


			$user           = $result->get('User');

			$this->result->result = true;
			$this->result->response = $user;

			return true;
		} catch (\Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e) {

			$this->error_message = $e->getAwsErrorMessage();
			$this->error_code    = $e->getAwsErrorCode();

			$this->result->result = false;
			$this->result->message = $this->error_message;

			return false;
		}
	}

	/*
   	 *  @param string --> Use email address
   	 *  @param string The new password to set
   	 *  @param bool Default is true , setting false will set password but makes AWS Cognito Status - FORCE_CHANGE_PASSWORD
   	 */
	public function resetUserPassword($username, $password, $permanent = true)
	{

		try {
			$result = $this->client->AdminSetUserPassword([
				'UserPoolId' => $this->poolId,
				'Permanent' => true,
				'Username' => $username,
				'Password' => $password
			]);

			return true;
		} catch (\Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e) {

			$this->error_message = $e->getAwsErrorMessage(); //Password does not conform to policy
			$this->error_code    = $e->getAwsErrorCode();   //"InvalidPasswordException"

			return false;
		}
	}

	public function updateForcePassword($session, $username, $password)
	{
		$challenge = ['USERNAME'	=> $username, 'NEW_PASSWORD' => $password];
		if (!empty($this->appSecret))
			$challenge['SECRET_HASH'] = $this->hash($username . $this->clientId);

		try {
			$result = $this->client->adminRespondToAuthChallenge([
				'ChallengeName' 		=> 'NEW_PASSWORD_REQUIRED',
				'ChallengeResponses' 	=> $challenge,
				'ClientId' 				=> $this->clientId,
				'UserPoolId'			=> $this->poolId,
				'Session' 				=> $session
			]);

			//on success, User could be logged in now, but better to let guard handle new credentials on login page
			if (!empty($result->get('AuthenticationResult')['AccessToken']))
				return true;
		} catch (\Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e) {

			$this->error_message = $e->getAwsErrorMessage();
			$this->error_code    = $e->getAwsErrorCode();

			throw \Illuminate\Validation\ValidationException::withMessages(['password' => [$this->error_message]]);
		}

		return false;
	}

	public function disableUser($username)
	{
		try {

			$result = $this->client->AdminDisableUser([
				'UserPoolId' => $this->poolId,
				'Username' => $username
			]);

			return true;
		} catch (\Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e) {

			$this->error_message = $e->getAwsErrorMessage();
			$this->error_code    = $e->getAwsErrorCode();

			return false;
		}
	}


	/*
   	 * 	Creates the AWS specific hash, the message provided will be specific such as username concatenated with clientid, etc.
   	 * 
   	 * 	@param str The message to hash
   	 * 	
   	 * 	@return str The generated hash
   	 */
	public function hash($str)
	{
		return base64_encode(hash_hmac('sha256', $str, $this->appSecret, true));
	}

	public function getUser($email)
	{
		try {
			$result = $this->client->adminGetUser(['UserPoolId' => $this->poolId, 'Username' => $email]);
			$cognito = new \stdClass();
			$cognito->Username = $result->get('Username');
			$cognito->UserCreateDate = $result->get('UserCreateDate')->__toString();
			$cognito->UserLastModifiedDate = $result->get('UserLastModifiedDate')->__toString();
			$cognito->Enabled = $result->get('Enabled');
			$cognito->UserStatus = $result->get('UserStatus');
			$cognito->attributes = [];
			$attributes = $result->get('UserAttributes');

			if (!empty($attributes))
				foreach ($attributes as $attribute)
					$cognito->attributes[] = ['Name' => $attribute['Name'], 'Value' => $attribute['Value']];

			$this->result = true;
			$this->payload = $cognito;

			return true;
		} catch (\Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e) {

			$this->error_message = $e->getAwsErrorMessage();
			$this->error_code    = $e->getAwsErrorCode();
		}

		return  false;
	}

	public function updateUserAttributes($email, $attributes)
	{
		try {

			$result = $this->client->adminUpdateUserAttributes(['UserPoolId' => $this->poolId, 'Username' => $email, 'UserAttributes' => $attributes]);

			return true;
		} catch (\Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e) {

			$this->error_message = $e->getAwsErrorMessage();
			$this->error_code    = $e->getAwsErrorCode();

			return  false;
		}


		return  false;
	}


	/*
   	 *  Make API call to permanently delete a cognito user
   	 *
   	 *  @param string The username to delete
   	 *  
   	 *  @return bool
   	 */
	public function deleteCognitoUser($name)
	{
		try {
			$result         = $this->client->adminDeleteUser([
				'UserPoolId' => $this->poolId,
				'Username' => $name
			]);


			//@todo need to set local user record as inactive, deleted , etc.
			return true;
		} catch (\Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e) {

			$this->error_message = $e->getAwsErrorMessage();
			$this->error_code    = $e->getAwsErrorCode();

			return false;
		}
	}

	/*
   	 *  Check if the current token has expired or is close to expiration
   	 * 
   	 *  @return bool
   	 */
	public function tokenNeedsRefresh()
	{

		return true;
		$expires = session('CognitoExpiry');
		if ($expires >= time() - 300) //pad by five minutes to refresh BEFORE expiration
			return true;

		return false;
	}

	/*
   	 *  
   	 * 
   	 *  @param str The Refresh token
   	 *  @param str The username, neccessary for hash secret
   	 * 
   	 *  @return bool
   	 */
	public function refreshToken($RefreshToken, $username)
	{
		try {
			$auth_parameters = ['REFRESH_TOKEN' => $RefreshToken];
			if (!empty($this->appSecret))
				$auth_parameters['SECRET_HASH'] = $this->hash($username . $this->clientId);

			$result = $this->client->InitiateAuth([
				'AuthFlow' 		 => self::REFRESH_TOKEN_AUTH,
				'ClientId' 		 => $this->clientId,
				'UserPoolId'	 => $this->poolId,
				'AuthParameters' => $auth_parameters
			]);
			$this->AccessToken 	= $result->get('AuthenticationResult')['AccessToken'];
			$this->IdToken 		= $result->get('AuthenticationResult')['IdToken'];

			session([
				'CognitoAccessToken'	=> $this->AccessToken,
				'CognitoIdToken'		=> $this->IdToken,
				'CognitoUsername'       => $username,
				'CognitoExpiry'         => time() + ($result->get('AuthenticationResult')['ExpiresIn'] * 1)
			]);

			return true;
		} catch (\Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException $e) {

			$this->error_message = $e->getAwsErrorMessage();
			$this->error_code    = $e->getAwsErrorCode();

			return false;
		}
	}
}
