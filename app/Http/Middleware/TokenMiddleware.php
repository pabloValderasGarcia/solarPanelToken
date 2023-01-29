<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use JWTAuth;

class TokenMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (\Exception $e) {
            if ($e instanceof e\TokenBlacklistedException || $e instanceof e\TokenInvalidException) {
                return response()->json(['message' => 'Invalid Token...']);
            } else if ($e instanceof e\TokenExpiredException) {
                return response()->json(['message' => 'Expired Token...']);
            } else {
                return response()->json(['message' => 'Token required...']);
            }
        }
        return $next($request);
    }
}
