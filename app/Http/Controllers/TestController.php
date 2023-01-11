<?php

namespace App\Http\Controllers;

 
class TestController extends Controller
{
    public function index()
    {
    	$endpoint = 'https://sandbox.api.myinfo.gov.sg/com/v4/authorize';
    	$appId = 'STG-201403826N-LAZADAPAY-ACCTVERIFY';
    	$callback = 'http://localhost:3001/callback';
    	$scope = 'name';
    	$purposeId = '512f9a47';
        $codeVerifier = 'hellow';

        $codeChallenge = $this->getCodeChallenge($codeVerifier);

        echo $endpoint . '?' . 'client_id=' . $appId .
        	'&scope=' . $scope . 
        	'&redirect_uri=' . $callback .
        	'&response_type=code' .
        	'&code_challenge=' . $codeChallenge .
        	'&code_challenge_method=S256' . 
        	'&purpose_id=' . $purposeId;
    }

    function getCodeChallenge($codeVerifier){
		$challengeBytes = hash('sha256', $codeVerifier, true);
		$codeChallenge = rtrim(strtr(base64_encode($challengeBytes), '+/', '-_'), '=');

		return $codeChallenge;
    }
}