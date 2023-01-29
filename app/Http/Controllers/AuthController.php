<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Carbon\Carbon;
use JWTAuth;

class AuthController extends Controller
{
    // CONSTRUCTOR
    function __construct() {
        $this->middleware('token')->only(['request', 'logout']);
    }
    
    // LOGIN
    function login(Request $request) {
        $validator = Validator::make($request->only('email', 'password'), [
            'email' => 'required|email|min:5|max:80',
            'password' => 'required|string|min:8'
        ]);
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()->toJson()], 422); // 422 => Unprocessable entity
        } else {
            $credentials = $request->only('email', 'password');
            $token = JWTAuth::attempt($credentials);
            if (!$token) {
                return response()->json([
                    'message' => 'Error: Unauthorized'
                ], 401); // 401 => Unauthorized
            }
            
            $payload = JWTAuth::setToken($token)->getPayload(); // Get JWT Data
            return response()->json([
                'message' => 'Successfully login',
                'authorization' => [
                    'token' => $token,
                    'token_type' => 'Bearer',
                    'expires_at' => Carbon::parse($payload->get('exp'))->addHour()->format('d M Y')
                ]
            ], 200); // 200 => OK
        }
    }
    
    // LOGOUT
    function logout(Request $request) {
        Auth::logout();
        return response()->json(['message' => 'Successfully logout']);
    }
    
    // REGISTER
    function register(Request $request) {
        $validator = Validator::make($request->only('name', 'email', 'password', 'password_confirmation'), [
            'name' => 'required|string|max:15',
            'email' => 'required|string|email|min:5|max:80|unique:users',
            'password' => 'required|string|required_with:password_confirmation|same:password_confirmation|min:8',
            'password_confirmation' => 'required|string|min:8'
        ]);
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()->toJson()], 400); // 400 => Bad request
        } else {
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => bcrypt($request->password),
            ]);
            return response()->json([
                'message' => 'Successfully register',
                'user' => $user
            ]);
        }
    }
    
    // REQUEST
    function request(Request $request) {
        // GET DATA (lat, long...) FROM MADRID CENTRE
        $url = 'https://api.sunrise-sunset.org/json?lat=40.41831&lng=-3.70275&date=' . date('Y-m-d') . '&formatted=0';
        $actualData = json_decode(file_get_contents($url));
        
        // TO HOURS, MINUTES AND SECONDS
        $results = $actualData->results;
        $from = explode('T', $results->sunrise)[1];
        $from = explode('+', $from)[0];
        $to = explode('T', $results->sunset)[1];
        $to = explode('+', $to)[0];
        
        // TO MINUTES
        $from = (intval(explode(':', $from)[0] * 60)) + (intval(explode(':', $from)[1]));
        $to = (intval(explode(':', $to)[0] * 60)) + (intval(explode(':', $to)[1]));
        $actualMinutes = (intval(date('H')) * 60) + (intval(date('i'))) + 60;
        
        // COS AND SIN
        $equation = (-pi() / 2) + ((((pi() / 2) - (-pi() / 2)) / ($to - $from)) * ($actualMinutes - $from));
        $cos = cos($equation);
        $sin = sin($equation);
            
        // CHECK IF IN TIME RANGE
        if ($actualMinutes >= $from && $actualMinutes <= $to) {
            return response()->json([
                'sin' => round($sin, 2),
                'cos' => round($cos, 2),
                'sensor1' => rand(0, 1),
                'sensor2' => rand(0, 1),
                'sensor3' => rand(0, 1),
                'sensor4' => rand(0, 1)
            ], 200); // 200 => OK
        } else {
            return response()->json([
                'message' => 'Out of sunny range... Come back tomorrow!',
                'sin' => 0,
                'cos' => 0,
                'sensor1' => rand(0, 1),
                'sensor2' => rand(0, 1),
                'sensor3' => rand(0, 1),
                'sensor4' => rand(0, 1)
            ], 418); // 418 => I'm a teapot :O
        }
    }
}
