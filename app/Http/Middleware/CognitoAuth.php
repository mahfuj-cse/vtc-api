<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Factory as Auth;

class CognitoAuth
{
    protected $auth;

    public function __construct(Auth $auth)
    {
        $this->auth = $auth;
    }

    public function handle($request, Closure $next, ...$guards)
    {
        $this->authenticate($request, ['AWSCognito']);

        if ($request->session('CognitoUsername') && $this->auth->user() && $this->auth->user()->active == 0) {
            $this->auth->logout();

            $request->session()->flash('message', 'You have been logged in.');

            return response()->json(['result' => false, 'response' => 'Inactive',  'auth' => 'logout']);
        }

        return $next($request);
    }

    protected function authenticate($request, array $guards)
    {
        if (session('CognitoNeedsReset') == true) {
            return true;
        }

        if (empty($guards))
            $guards = [null];

        foreach ($guards as $index => $guard) {

            if ($this->auth->guard($guard)->check($request)) {

                return true;
            }
        }

        $current = parse_url(url()->current());
        $request->session()->flash('message', 'You are not logged in.');
        $request->session()->put('routeTo', $current['path']);

        throw new AuthenticationException('Unauthenticated.', $guards, '/login');
    }
}
