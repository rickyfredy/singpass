<?php

namespace App\Http\Controllers;

use Illuminate\Support\Str;
use Illuminate\Support\Facades\Storage;
use Illuminate\Http\Request;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Serializer\CompactSerializer;

define('HOSTPRD', 'https://api.myinfo.gov.sg');
define('HOSTPRE', 'https://test.api.myinfo.gov.sg');
define('PATHPUBLICKEY', '/app/jwk/pre_cupu_app.crt');
define('PATHPRIVATEKEY', '/app/jwk/pre.cupuapp.key');
define('CODEVERIFIER', '%2BaU3NYPUsP0cbk5%2BSAWtlFkKWG5hPllumdEuYiVSOpQ%3D');
define('CODECHALLENGE', 'Z2nQOxb0tXNZX0I72iL7L58vCkL4siVSXW%2F3WhDP0Yo%3D');
 
class TestController extends Controller
{
    public function prd()
    {
        $endpoint = HOSTPRD . '/com/v4/authorize';
        $appId = 'PROD-201403826N-LAZADAPAY-ACCTVERIFY';
        $callback = 'https://cupu.app/login/success';
        $scope = 'name';
        $purposeId = '562225ca';
        $codeChallenge = CODECHALLENGE;

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
        // $codeVerifier = urlencode(base64_encode(random_bytes(32)));
        // $codeChallenge = $this->getCodeChallenge($codeVerifier);
        // echo 'codeVerifier: ' . $codeVerifier . '<br />';
        // echo 'codeChallenge: ' . $codeChallenge . '<br />';
        // dd();

        $endpoint = HOSTPRE . '/com/v4/authorize';
        $appId = 'STG-201403826N-LAZADAPAY-ACCTVERIFY';
        $callback = 'https://pre.cupu.app/login/success';
        $scope = 'name';
        $purposeId = 'e6439d08';
        $codeChallenge = CODECHALLENGE;

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
        $encryptedCodeVerifier = hash('sha256', $codeVerifier, true);

        return urlencode(base64_encode($encryptedCodeVerifier));
        // $codeChallenge = rtrim(strtr(base64_encode($challengeBytes), '+/', '-_'), '=');

        // return $codeChallenge;
    }

    public function successLogin(Request $request)
    {
        $publicKeyPath = storage_path(PATHPUBLICKEY);
        $privateKeyPath = storage_path(PATHPRIVATEKEY);

        $endpoint = HOSTPRE . '/com/v4/token';
        $appId = 'STG-201403826N-LAZADAPAY-ACCTVERIFY';
        $authCode = $request->input('code');
        $callback = 'https://pre.cupu.app/get/token';
        $codeVerifier = CODEVERIFIER;
        $grantType = 'authorization_code';
        $clientAssertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        $jwkThumbprint = $this->generateJwkThumbprint($publicKeyPath);
        $clientAssertion = $this->generateClientAssertion($endpoint, $appId, $privateKeyPath, $jwkThumbprint);

        $dpop = $this->generateDpop($endpoint, 'POST', $publicKeyPath, $privateKeyPath, null);


        $response = Http::asForm()
            ->withHeaders([
                'Cache-Control' => 'no-cache',
                'DPoP' => $dpop
            ])
            ->post('http://example.com/users', [
                'grant_type' => $grantType,
                'code' => $authCode,
                'redirect_uri' => $callback,
                'client_id' => $appId,
                'code_verifier' => $codeVerifier,
                'client_assertion_type' => $clientAssertionType,
                'client_assertion' => $clientAssertion
            ]);


        var_dump($response);
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

    function generateClientAssertion($tokenUrl, $clientId, $privateKeyPath, $jwkThumbprint){

        $jwk = JWKFactory::createFromKeyFile(
            $privateKeyPath,
            null,
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
                'jkt' => $jwkThumbprint
            ]
        ]);

        // JWS
        $algorithmManager = new AlgorithmManager([
            new RS256(),
        ]);

        $jwsBuilder = new JWSBuilder($algorithmManager);

        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($jwk, ['alg' => 'RS256', 'typ' => 'JWT'])
            ->build();

        $serializer = new CompactSerializer(); // The serializer

        return $serializer->serialize($jws, 0);
    }

    function generateDpop($url, $method, $publicKeyPath, $privateKeyPath, $ath){
        $timestamp = date();

        $payload = [
            'htu' => url,
            'htm' => method,
            'jti' => Str::random(40),
            'iat' => $timestamp,
            'exp' => $timestamp + 120,
        ];

        if (!empty($ath)){
            $payload['ath'] = $ath;
        }


        // JWK
        $jwk = JWKFactory::createFromCertificateFile(
            $publicKeyPath,
            [
                'use' => 'sig',
            ]
        );


        // JWS
        $algorithmManager = new AlgorithmManager([
            new ES256(),
        ]);

        $jwsBuilder = new JWSBuilder($algorithmManager);

        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($jwk, ['alg' => 'ES256', 'typ' => 'dpop+jwt', 'jwk' => $jwk->jsonSerialize()])
            ->build();

        $serializer = new CompactSerializer(); // The serializer

        return $serializer->serialize($jws, 0);
    }

    public function successToken(Request $request)
    {
        echo 'Success get token';
    }

    public function jwks(){

        $publicKeyPath = storage_path(PATHPUBLICKEY);

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
    }

}