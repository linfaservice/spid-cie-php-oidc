<?php

require_once('JWT.php');

class EndpointToken extends Endpoint {

    public $name = "Token Endpoint";

    function __construct($config, $db) {
        parent::__construct($config, $db);
    }

    function process() {
        // allow json body data
        if(!count($_POST)) $_POST = json_decode(file_get_contents('php://input'), true);

        $clients        = $this->config['clients'];
        $code           = $_POST['code'] ?? '';
        $scope          = $_POST['scope'] ?? '';
        $grant_type     = $_POST['grant_type'] ?? '';
        $client_id      = $_POST['client_id'] ?? '';
        $client_secret  = $_POST['client_secret'] ?? '';
        $redirect_uri   = $_POST['redirect_uri'] ?? '';
        $state          = $_POST['state'] ?? '';

        try {
            $credential = $this->getBasicAuthCredential();
            if($credential!=false && is_array($credential)) {
                $this->db->log("TOKEN Credential", var_export($credential, true));
                syslog(LOG_INFO, 'OIDC Token Endpoint Credential: ' . json_encode($credential));

                $username = $credential['username'];
                $password = $credential['password'];

                $auth_method = $clients[$username]['token_endpoint_auth_method'];
                $this->db->log("TOKEN configured auth_method", var_export($auth_method, true));
                syslog(LOG_INFO, 'OIDC Token Endpoint Auth Method: ' . json_encode($auth_method));

                switch($auth_method) { 
                    case 'client_secret_post':
                        // already have client_id and client_secret
                        break;
                    case 'client_secret_basic':
                    default:
                        $client_id = $username;
                        $client_secret = $password;
                        break;
                }
            }
        
            $this->db->log("TOKEN", var_export($_POST, true));
            syslog(LOG_INFO, 'OIDC Token Endpoint Request Body: ' . json_encode($_POST));
    
            if(strpos($scope, 'openid')<0) throw new Exception('invalid_scope');
            if(strpos($scope, 'profile')<0) throw new Exception('invalid_scope');
            if($grant_type!='authorization_code') throw new Exception('invalid_request');
            if(!in_array($client_id, array_keys($clients))) throw new Exception('invalid_client');
            if(!$redirect_uri && count($clients[$client_id]['redirect_uri'])==1) $redirect_uri = $clients[$client_id]['redirect_uri'][0];
            if(!in_array($redirect_uri, $clients[$client_id]['redirect_uri'])) throw new Exception('invalid_redirect_uri');
            if(!$this->db->checkAuthorizationCode($client_id, $redirect_uri, $code)) throw new Exception('invalid_code');
    
            $access_token = $this->db->createAccessToken($code);
            $userinfo = (array) $this->db->getUserinfo($access_token);
            $request = $this->db->getRequestByCode($code);
    
            $subject = $userinfo['fiscalNumber'];
            $exp_time = 1800;
            $iss = $this->config['spid-php-proxy']['origin'];
            $aud = $client_id;
            $jwk_pem = $this->config['jwt_private_key'];
            $nonce = $request['nonce'];
            
            $id_token = JWT::makeIdToken($subject, $exp_time, $iss, $aud, $nonce, $jwk_pem);
            
            $this->db->saveIdToken($request['req_id'], $id_token);
    
            $this->db->log("ID_TOKEN", $id_token);
    
            header('Content-Type: application/json; charset=utf-8');
            $response = json_encode(array(
                "access_token" => $access_token,
                "token_type" => "Bearer",
                "expires_in" => 1800,
                "id_token" => $id_token
            ));

            syslog(LOG_INFO, 'OIDC Token Endpoint Response: ' . $response);
            echo $response;
    
        } catch(Exception $e) {
            http_response_code(400);
            if($this->config['debug']) {
                echo "ERROR: ".$e->getMessage();
                $this->db->log("TOKEN_ERR", $e->getMessage());
                syslog(LOG_INFO, 'OIDC Token Endpoint Error: ' . $e->getMessage());
            } 
        }
    }


    /**
     * Get username e password of Basic Authentication
     */
    function getBasicAuthCredential() {
        $credential = false;
        $authHeader = $this->getAuthorizationHeader();
        $this->db->log("TOKEN BASIC AUTH", var_export($authHeader, true));
        if(substr($authHeader, 0, 5)=='Basic') {
            $creds = base64_decode(substr($authHeader, 6));
            $creds_array = explode(":", $creds);
            $credential = array(
                'username' => $creds_array[0],
                'password' => $creds_array[1]
            );
        } 
        
        return $credential;
    }
    
    /** 
     * Get hearder Authorization
     * */
    function getAuthorizationHeader() {
        $headers = null;
        if (isset($_SERVER['Authorization'])) {
            $headers = trim($_SERVER["Authorization"]);
        }
        else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
            $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
            //print_r($requestHeaders);
            if (isset($requestHeaders['Authorization'])) {
                $headers = trim($requestHeaders['Authorization']);
            }
        }
        return $headers;
    }
}