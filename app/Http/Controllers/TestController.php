<?php

namespace App\Http\Controllers;

 
class TestController extends Controller
{
    public function prd()
    {
        $endpoint = 'https://api.myinfo.gov.sg/com/v4/authorize';
        $appId = 'PROD-201403826N-LAZADAPAY-ACCTVERIFY';
        $callback = 'https://cupu.app/login/success';
        $scope = 'name';
        $purposeId = '562225ca';
        $codeVerifier = 'hellow';

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
        $endpoint = 'https://test.api.myinfo.gov.sg/com/v4/authorize';
        $appId = 'STG-201403826N-LAZADAPAY-ACCTVERIFY';
        $callback = 'https://pre.cupu.app/login/success';
        $scope = 'name';
        $purposeId = 'e6439d08';
        $codeVerifier = 'hellow';

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

    public function success()
    {
        echo 'Hellow doc';
    }
}