<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});



Route::post('/authenticate', [UserController::class, 'authenticate']);
Route::get('/list-users', [UserController::class, 'listUsers']);
Route::post('/create-user', [UserController::class, 'createUser']);
Route::put('/update-user-attributes/{username}', [UserController::class, 'updateUserAttributes']);
Route::post('/signup', [UserController::class, 'signUp']);

Route::put('/update', [UserController::class, 'getUserByEmail']);
Route::get('/authenticated-user', [UserController::class, 'getAuthenticatedUser']);



// Add more routes as needed
