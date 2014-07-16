<?php
/**
 * Copyright 2013 Nomura Research Institute, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once('libjsoncrypto.php');


function test_jws()
{

    printf("JWS tests\n========\n");
    $data = 'The Quick Brown Fox Jumps Over the Lazy Dog.';
    $key = 'SomeSecretKeyMaterial';

    printf("Data = %s\nKey = %s\n\n", $data, $key);
    $algs = array('NONE', 'HS256', 'HS384', 'HS512');
    foreach($algs as $alg) {
        printf("    %s : ", $alg);
        $sig_params = array(
            'kid' => 'Key00',
            'alg' => $alg
        );
        $jws = jwt_sign($data, $sig_params, $key);
        printf("    JWS = %s\n", $jws);
        $verified = jwt_verify($jws, $key);
        printf("    JWS verified : %d\n\n", $verified);
    }

    $algs = array('RS256', 'RS384', 'RS512');
    foreach($algs as $alg) {
        printf("    %s : ", $alg);
        $sig_params = array(
            'kid' => 'Key00',
            'alg' => $alg
        );

        $private_key = array(
            'key_file' => 'private.key',
            'password' => ''
        );

        $public_key = array(
            'pem' => 'public.key'
        );

        $public_jwk = array('jwk' => file_get_contents('public.jwk'));

        $jws = jwt_sign($data, $sig_params, $private_key);
        printf("    JWS = %s\n", $jws);
        $verified = jwt_verify($jws, $public_key);
        printf("    JWS verified : %d\n", $verified);
        $jwk_verified = jwt_verify($jws, $public_jwk);
        printf("    JWS verified with JWK: %d\n\n", $jwk_verified);
    }

}


function test_jwe()
{
    printf("JWE tests with public key\n========\n");
    $data = 'A MAN A PLAN A CANAL PANAMA';
    printf("Plaintext = %s\n\n", $data);
    $algs = array('RSA1_5', 'RSA-OAEP');
    $encs = array('A128CBC-HS256', 'A256CBC-HS512', 'A128GCM', 'A256GCM');

    foreach($algs as $alg) {
        foreach($encs as $enc) {
            printf("alg = %s enc = %s\n", $alg, $enc);
            $jwe = jwt_encrypt($data, 'public.key', false, null, null, null, $alg, $enc,true);
            printf("jwe = %s\n", $jwe);
            $plaintext = jwt_decrypt($jwe, 'private.key');
            if($plaintext)
                printf("Decrypted text = %s\n\n", $plaintext);
            else
                printf("failed decryption\n\n");
        }
    }

    printf("JWE tests with public JWK\n========\n");
    $jwks = file_get_contents('public.jwk');
    $jwk = jwk_get_rsa_enc_key($jwks);
    foreach($algs as $alg) {
        foreach($encs as $enc) {
            printf("alg = %s enc = %s\n", $alg, $enc);
            $jwe = jwt_encrypt($data, $jwk, false, null, null, null, $alg, $enc,true);
            printf("jwe = %s\n", $jwe);
            $plaintext = jwt_decrypt($jwe, 'private.key');
            if($plaintext)
                printf("Decrypted text = %s\n\n", $plaintext);
            else
                printf("failed decryption\n\n");
        }
    }

}


test_jws();
test_jwe();