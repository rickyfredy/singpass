<?php

namespace App\Http\Controllers;

use Illuminate\Support\Str;
use Illuminate\Support\Facades\Storage;
use Illuminate\Http\Request;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Serializer\CompactSerializer;

define('HOSTPRD', 'https://api.myinfo.gov.sg');
define('HOSTPRE', 'https://test.api.myinfo.gov.sg');
 
class TestController extends Controller
{
    public function prd()
    {
        $endpoint = HOSTPRD . '/com/v4/authorize';
        $appId = 'PROD-201403826N-LAZADAPAY-ACCTVERIFY';
        $callback = 'https://cupu.app/login/success';
        $scope = 'name';
        $purposeId = '562225ca';
        $codeVerifier = random_bytes(32);

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
        $endpoint = HOSTPRE . '/com/v4/authorize';
        $appId = 'STG-201403826N-LAZADAPAY-ACCTVERIFY';
        $callback = 'https://pre.cupu.app/login/success';
        $scope = 'name';
        $purposeId = 'e6439d08';
        $codeVerifier = random_bytes(32);

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

        $publicKeyPath = storage_path('/app/jwk/pre_cupu_app.crt');
        $privateKeyPath = storage_path('/app/jwk/pre.cupuapp.key');

        $endpoint = HOSTPRE . '/com/v4/token';
        $appId = 'STG-201403826N-LAZADAPAY-ACCTVERIFY';
        $authCode = $request->input('code');
        $callback = 'https://pre.cupu.app/get/token';
        $codeVerifier = random_bytes(32);
        $grantType = 'authorization_code';
        $clientAssertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        $jktThumbprint = $this->generateJwkThumbprint($publicKeyPath);
        $clientAssertion = $this->generateClientAssertion($endpoint, $appId, $privateKeyPath, $jktThumbprint);

        $url = $endpoint . '?' . 'grant_type=' . $grantType .
            '&code=' . $authCode .
            '&redirect_uri=' . $callback .
            '&client_id=' . $appId .
            '&code_verifier=' . $codeVerifier .
            '&client_assertion_type=' . $clientAssertionType .
            '&client_assertion=' . $clientAssertion;

        echo 'Redirect to get Token ------> ' . $url;

        // header('Location: ' . $url);
    }

    function generateJwkThumbprint($publicKeyPath){
        $jwk = JWKFactory::createFromCertificateFile(
            $publicKeyPath,
            [
                'use' => 'sig',
            ]
        );

        $jwkThumbprint = $jwk->thumbprint('sha256');

        return $jwkThumbprint;
    }

    function generateClientAssertion($tokenUrl, $clientId, $privateKeyPath, $jktThumbprint){

        $jwk = JWKFactory::createFromCertificateFile(
            $privateKeyPath,
            [
                'use' => 'sig',
            ]
        );
        
        $timestamp = time();
        $randomStr = Str::random(40);

        $payload = json_encode([
            'sub' => $clientId,
            'jti' => $randomStr,
            'aud' => $tokenUrl,
            'iss' => $clientId,
            'iat' => $timestamp,
            'exp' => $timestamp + 300,
            'cnf' => [
                'jkt' => $jktThumbprint
            ]
        ]);

        // Builder
        $algorithmManager = new AlgorithmManager([
            new PS256(),
        ]);

        $jwsBuilder = new JWSBuilder($algorithmManager);

        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($jwk, ['alg' => 'PS256']) // We add a signature with a simple protected header
            ->build();

        $serializer = new CompactSerializer(); // The serializer

        return $serializer->serialize($jws, 0);
    }

    public function successToken(Request $request)
    {
    }

    public function jwks(){

        $publicKeyPath = storage_path('/app/jwk/pre_cupu_app.crt');

        $jwk = JWKFactory::createFromCertificateFile(
            $publicKeyPath,
            [
                'use' => 'sig',
            ]
        );

        $jwkThumbprint = $jwk->thumbprint('sha256');

        $jwkSet = new JWKSet([$jwk]);

        $jwkSetJson = $jwkSet->jsonSerialize();

        return response($jwkSetJson, 200)
            ->header('Content-Type', 'application/json');


        // $pem = Storage::get('jwk\public-key.pem');

        // $options = [
        //    'use' => 'sig',
        //    'alg' => 'RS256',
        //    'kid' => 'eXaunmL',
        // ];

        // $keyFactory = new KeyFactory();
        // $key = $keyFactory->createFromPem($pem, $options);

        // $keySet = [
        //     'keys' => [$key]
        // ];

        // return response($keySet, 200)
        //     ->header('Content-Type', 'application/json');
    }

}