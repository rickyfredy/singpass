<?php

use Illuminate\Support\Facades\Route;

use App\Http\Controllers\TestController;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

// Route::get('/', function () {
//     return view('welcome');
// });

Route::group(array('domain' => 'cupu.app'), function()
{
    Route::get('/', [TestController::class, 'prd']);
});

Route::group(array('domain' => 'pre.cupu.app'), function()
{
	Route::get('/', [TestController::class, 'pre']);
});


Route::group(array('domain' => 'localhost'), function()
{
	Route::get('/', [TestController::class, 'pre']);
});


Route::get('/login/success', [TestController::class, 'success']);