<?php
    require_once("../vendor/autoload.php");

    use Jose\Component\Core\AlgorithmManager;
    use Jose\Component\Core\JWK;
    use Jose\Component\KeyManagement\JWKFactory;
    use Jose\Component\Signature\Algorithm\RS256;  
    use Jose\Component\Signature\JWSBuilder;
    use Jose\Component\Signature\Serializer\JWSSerializerManager;
    use Jose\Component\Signature\Serializer\CompactSerializer as JWSSerializer;
    use Jose\Component\Signature\JWSVerifier;
    use Jose\Component\Signature\JWSLoader;
    use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
    use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
    use Jose\Component\Encryption\Compression\CompressionMethodManager;
    use Jose\Component\Encryption\Compression\Deflate;
    use Jose\Component\Encryption\JWEBuilder; 
    use Jose\Component\Encryption\Serializer\JWESerializerManager;
    use Jose\Component\Encryption\Serializer\CompactSerializer as JWESerializer;
    use Jose\Component\Encryption\JWEDecrypter;

    const DEFAULT_SECRET = "";
    const DEFAULT_TOKEN_EXPIRATION_TIME = 1200;


    class JWT {

        static function makeJWE($payload, $exp_time, $iss, $aud, $secret): string {
            
            $iat        = new DateTimeImmutable();
            $exp_time   = $exp_time?: DEFAULT_TOKEN_EXPIRATION_TIME;
            $exp        = $iat->modify("+".$exp_time." seconds")->getTimestamp();

            $data = [
                'iss'  => $iss,                                     // Issuer - spDomain
                'aud'  => $aud,                                     // Audience - Redirect_uri
                'iat'  => $iat->getTimestamp(),                     // Issued at: time when the token was generated
                'nbf'  => $iat->getTimestamp(),                     // Not before
                'exp'  => $exp,                                     // Expire
                'data' => $payload,                                 // Authentication Data
            ];

            $keyEncryptionAlgorithmManager = new AlgorithmManager([ new A256KW() ]); 
            $contentEncryptionAlgorithmManager = new AlgorithmManager([ new A256CBCHS512() ]);
            $compressionMethodManager = new CompressionMethodManager([ new Deflate() ]);

            $jweBuilder = new JWEBuilder(
                $keyEncryptionAlgorithmManager,
                $contentEncryptionAlgorithmManager,
                $compressionMethodManager
            );

            $jwk = JWKFactory::createFromSecret($secret?:DEFAULT_SECRET);

            $jwe = $jweBuilder
                ->create()
                ->withPayload(json_encode($data))
                ->withSharedProtectedHeader([
                    'alg' => 'A256KW',
                    'enc' => 'A256CBC-HS512',
                    'zip' => 'DEF'
                ])
                ->addRecipient($jwk) 
                ->build();

            $serializer = new JWESerializer();
            $token = $serializer->serialize($jwe, 0); 

            return $token;
        }

        static function makeJWS($payload, $exp_time, $iss, $aud, $jwk_pem): string {
            
            $iat        = new DateTimeImmutable();
            $exp_time   = $exp_time?: DEFAULT_TOKEN_EXPIRATION_TIME;
            $exp        = $iat->modify("+".$exp_time." seconds")->getTimestamp();

            $data = [
                'iss'  => $iss,                                     // Issuer - spDomain
                'aud'  => $aud,                                     // Audience - Redirect_uri
                'iat'  => $iat->getTimestamp(),                     // Issued at: time when the token was generated
                'nbf'  => $iat->getTimestamp(),                     // Not before
                'exp'  => $exp,                                     // Expire
                'data' => $payload,                                 // Authentication Data
            ];

            $algorithmManager = new AlgorithmManager([new RS256()]);
            $jwk = JWKFactory::createFromKeyFile($jwk_pem);
            $jwsBuilder = new JWSBuilder($algorithmManager);
            $jws = $jwsBuilder
                ->create() 
                ->withPayload(json_encode($data)) 
                ->addSignature($jwk, ['alg' => 'RS256']) 
                ->build(); 
            
            $serializer = new JWSSerializer(); 
            $token = $serializer->serialize($jws, 0); 
        
            return $token;
        }

        static function makeIdToken($subject, $exp_time, $iss, $aud, $nonce, $jwk_pem): string {
            
            $iat        = new DateTimeImmutable();
            $exp_time   = $exp_time?: DEFAULT_TOKEN_EXPIRATION_TIME;
            $exp        = $iat->modify("+".$exp_time." seconds")->getTimestamp();

            $data = [
                'iss'  => $iss,                                     // Issuer - spDomain
                'aud'  => $aud,                                     // Audience - Redirect_uri
                'iat'  => $iat->getTimestamp(),                     // Issued at: time when the token was generated
                'nbf'  => $iat->getTimestamp(),                     // Not before
                'exp'  => $exp,                                     // Expire
                'sub'  => $subject,                                 // Subject Data
                'nonce'=> $nonce,
            ];

            $algorithmManager = new AlgorithmManager([new RS256()]);
            $jwk = getKeyJWK($jwk_pem);
            $jwsBuilder = new JWSBuilder($algorithmManager);
            $jws = $jwsBuilder
                ->create() 
                ->withPayload(json_encode($data)) 
                ->addSignature($jwk, ['alg' => 'RS256']) 
                ->build(); 
            
            $serializer = new JWSSerializer(); 
            $token = $serializer->serialize($jws, 0); 
        
            return $token;
        }

        static function getKeyJWK($file, $secret=null, $use='sig') {
            $jwk = JWKFactory::createFromKeyFile($file, $secret, ['use' => $use]);
            return $jwk;
        }

        static function getCertificateJWK($file, $use='sig') {
            $jwk = JWKFactory::createFromCertificateFile($file, ['use' => $use]);
            return $jwk;
        }
    }
