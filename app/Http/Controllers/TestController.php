<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
 
class TestController extends Controller
{
    // https://pre.cupu.app/login/success?code=myinfo-com-mqXXSI1oG5NGrXrZIpBM9jKuBz1K9AGi0ZPC0STX

    $hostPrd = 'https://api.myinfo.gov.sg';
    $hostPre = 'https://test.api.myinfo.gov.sg';

    $codeVerifier = 'codeVerifier';

    public function prd()
    {
        $endpoint = $this->hostPrd . '/com/v4/authorize';
        $appId = 'PROD-201403826N-LAZADAPAY-ACCTVERIFY';
        $callback = 'https://cupu.app/login/success';
        $scope = 'name';
        $purposeId = '562225ca';
        $codeVerifier = $this->codeVerifier;

        $codeChallenge = $this->getCodeChallenge($codeVerifier);

        $url = $endpoint . '?' . 'client_id=' . $appId .
            '&scope=' . $scope . 
            '&redirect_uri=' . $callback .
            '&response_type=code' .
            '&code_challenge=' . $codeChallenge .
            '&code_challenge_method=S256' . 
            '&purpose_id=' . $purposeId;


        header('Location: ' . $url);
    }

    public function pre()
    {
        $endpoint = $this->hostPre . '/com/v4/authorize';
        $appId = 'STG-201403826N-LAZADAPAY-ACCTVERIFY';
        $callback = 'https://pre.cupu.app/login/success';
        $scope = 'name';
        $purposeId = 'e6439d08';
        $codeVerifier = $this->codeVerifier;

        $codeChallenge = $this->getCodeChallenge($codeVerifier);

        $url = $endpoint . '?' . 'client_id=' . $appId .
            '&scope=' . $scope . 
            '&redirect_uri=' . $callback .
            '&response_type=code' .
            '&code_challenge=' . $codeChallenge .
            '&code_challenge_method=S256' . 
            '&purpose_id=' . $purposeId;


        header('Location: ' . $url);
    }

    function getCodeChallenge($codeVerifier){
        $challengeBytes = hash('sha256', $codeVerifier, true);
        $codeChallenge = rtrim(strtr(base64_encode($challengeBytes), '+/', '-_'), '=');

        return $codeChallenge;
    }

    public function successLogin(Request $request)
    {
        // https://sandbox.api.myinfo.gov.sg/com/v4/token

        $endpoint = $this->hostPre . '/com/v4/token';
        $appId = 'STG-201403826N-LAZADAPAY-ACCTVERIFY';
        $authCode = $request->input('code');
        $callback = 'https://pre.cupu.app/get/token';
        $codeVerifier = $this->codeVerifier;
        $grantType = 'authorization_code';
        $clientAssertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        $jktThumbprint = $this->generateJwkThumbprint('');
        $clientAssertion = $this->generateClientAssertion('', '', '', '');

        $url = $endpoint . '?' . 'grant_type=' . $grantType .
            '&code=' . $authCode .
            '&redirect_uri=' . $redirectUrl .
            '&client_id=' . $clientId .
            '&code_verifier=' . $codeVerifier .
            '&client_assertion_type=' . $clientAssertionType .
            '&client_assertion=' . $clientAssertion;

        echo 'Redirect to get Token ------> ' . $url;
    }

    function generateJwkThumbprint($publicKey){
        return '';
    }

    function generateClientAssertion($tokenUrl, $clientId, $privateSigningKey, $jktThumbprint){
        return '';
    }

    public function successToken(Request $request)
    {
    }

}