<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        try {
            // Dieu kien kiem tra email va password
            $request->validate([
                'email' => 'email|required',
                'password' => 'required'
            ]);

            //Truy cap input email va password
            $credentials = request(['email', 'password']);

            // Neu khong trung tai khoan thong bao 500 -> error
            if (!Auth::attempt($credentials)) {
                return response()->json([
                    'status_code' => 500,
                    'message' => 'Unauthorized'
                ]);
            }
            // Lay user co email giong
            $user = User::where('email', $request->email)->first();
            // Neu khong trung thong bao loi login
            if (!Hash::check($request->password, $user->password, [])) {
                throw new \Exception('Error in Login');
            }
            //Tao token tra ve truy van du lieu user neu khong thoa man nhung dieu tren
            $tokenResult = $user->createToken('authToken')->plainTextToken;
            return response()->json([
                'status_code' => 200,
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
            ]);
        } catch (\Exception $error) {
            // Bao loi login
            return response()->json([
                'status_code' => 500,
                'message' => 'Error in Login',
                'error' => $error,
            ]);
        }
    }
}
