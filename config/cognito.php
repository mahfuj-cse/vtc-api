<?php
return [
    'account'           => env('AWS_COGNITO_ACCOUNT'),
    'region'            => env('AWS_COGNITO_REGION', ''),
    'version'           => env('AWS_COGNITO_VERSION', 'latest'),
    'user_pool_id'      => env('AWS_COGNITO_USER_POOL_ID', ''),
    'app_client_id'     => env('AWS_COGNITO_APP_CLIENT_ID', ''),
    'app_secret'        => env('AWS_COGNITO_APP_SECRET', ''),
    'identity_pool_id'  => env('AWS_COGNITO_IDENTITY_POOL_ID', ''),
    'credentials'       => [
        'key'    => env('AWS_COGNITO_KEY', ''),
        'secret' => env('AWS_COGNITO_SECRET', '')
    ]
];
