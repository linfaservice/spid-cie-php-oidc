<?php

require('JWT.php');

class EndpointToken extends Endpoint {

    public $name = "Token Endpoint";

    function __construct($config, $db) {
        parent::__construct($config, $db);
    }

    function process() {

        $clients        = $this->config['clients'];
        $code           = $_POST['code'];
        $scope          = $_POST['scope'];
        $grant_type     = $_POST['grant_type'];
        $client_id      = $_POST['client_id'];
        $client_secret  = $_POST['client_secret'];
        $redirect_uri   = $_POST['redirect_uri'];
        $state          = $_POST['state'];
    
        $this->db->log("TOKEN", var_export($_POST, true));
    
        try {
            if(strpos($scope, 'openid')<0) throw new Exception('invalid_scope');
            if(strpos($scope, 'profile')<0) throw new Exception('invalid_scope');
            if($grant_type!='authorization_code') throw new Exception('invalid_request');
            if(!in_array($client_id, array_keys($clients))) throw new Exception('invalid_client');
            if(!in_array($redirect_uri, $clients[$client_id]['redirect_uri'])) throw new Exception('invalid_redirect_uri');
            if(!$this->db->checkAuthorizationCode($client_id, $redirect_uri, $code)) throw new Exception('invalid_code');
    
            $access_token = $this->db->createAccessToken($code);
            $userinfo = (array) $this->db->getUserinfo($access_token);
    
            $subject = $userinfo['fiscalNumber'];
            $exp_time = 1800;
            $iss = $this->config['spid-php-proxy']['origin'];
            $aud = $redirect_uri;
            $jwk_pem = $this->config['jwt_private_key'];
    
            $id_token = JWT::makeIdToken($subject, $exp_time, $iss, $aud, $jwk_pem);
            $request = $this->db->getRequestByCode($code);
            $this->db->saveIdToken($request['req_id'], $id_token);
    
            $this->db->log("ID_TOKEN", $id_token);
    
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(array(
                "access_token" => $access_token,
                "token_type" => "Bearer",
                "expires_in" => 1800,
                "id_token" => $id_token
            ));
    
        } catch(Exception $e) {
            http_response_code(400);
            if($this->config['debug']) {
                echo "ERROR: ".$e->getMessage();
                $this->db->log("TOKEN_ERR", $e->getMessage());
            } 
        }
    }
}