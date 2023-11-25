<?php

namespace App\Providers;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Auth;
use Illuminate\Foundation\Application;
use Illuminate\Validation\Validator;
use App\Auth\CognitoGuard;
use App\Auth\CognitoClient;
use Illuminate\Auth\EloquentUserProvider;

class CognitoServiceProvider extends ServiceProvider
{    
    public function boot()
    {              	
		$this->app->singleton(CognitoClient::class, function (Application $app) {
    	 	
		    $config = [ 'version'     => config('cognito.version'),
                	    'region'      => config('cognito.region'),
                		'credentials' => config('cognito.credentials') ];
		    
            return new CognitoClient(
                new CognitoIdentityProviderClient($config),
                config('cognito.app_client_id'),                
                config('cognito.user_pool_id'),
                config('cognito.app_secret'),
                config('cognito.region'),
                config('cognito.identity_pool_id'),
                config('cognito.version'),
                config('cognito.credentials'),
                config('cognito.account'),
                $config
            );
        });
        
        Auth::extend('CognitoGuard', function( $app, $name, array $config) {

        	$guard = new CognitoGuard(	'ctfn',
                						$client = $app->make(CognitoClient::class),
        	                            new EloquentUserProvider( $this->app['hash'], \App\Models\User::class ),
                						$app['session.store'],
                						$app['request'],
                						$this->app['hash']
            );
            
            $guard->setDispatcher($this->app['events']);
            $guard->setCookieJar($this->app['cookie']);            
            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));
            
            return $guard;
        });     
    }       
}