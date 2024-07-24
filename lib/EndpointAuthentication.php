<?php

require_once('JWT.php');

class EndpointAuthentication extends Endpoint {

    public $name = "Authentication Endpoint";

    function __construct($config, $db) {
        parent::__construct($config, $db);
    }

    function process() {

        $clients        = $this->config['clients'];
        $scope          = $_GET['scope'];
        $response_type  = $_GET['response_type'];
        $client_id      = $_GET['client_id'];
        $redirect_uri   = $_GET['redirect_uri'];
        $state          = $_GET['state'];
        $nonce          = $_GET['nonce'];
        $request        = $_GET['request'];
    
        $this->db->log("AUTH", var_export($_GET, true));


        //TODO: get params from request param
        //$request = JWT::decode($request);
        //$state = $request->state;
        //$redirect_uri = $request->redirect_uri;

        try {
            if(strpos($scope, 'openid')<0) throw new Exception('invalid_scope');
            if(strpos($scope, 'profile')<0) throw new Exception('invalid_scope');
            if($response_type!='code') throw new Exception('invalid_request');
            if(!in_array($client_id, array_keys($clients))) throw new Exception('invalid_client');
            if(!in_array($redirect_uri, $clients[$client_id]['redirect_uri'])) throw new Exception('invalid_redirect_uri');
    
            $req_id = $this->db->updateRequest($client_id, $redirect_uri, $state, $nonce);
            if($req_id==null) {
                $req_id = $this->db->createRequest($client_id, $redirect_uri, $state, $nonce);
            }

            $url = '';
            
            $login_url = $this->config['spid-php-proxy']['login_url'];
            if(strpos($login_url, '?')>-1) $url = $login_url . '&';
            else $url = $login_url . '?';
            
            $url .= 'client_id='.$this->config['spid-php-proxy']['client_id']
            .'&level='.$this->config['clients'][$client_id]['level']
            .'&redirect_uri='.$this->config['spid-php-proxy']['redirect_uri']
            .'&state='.base64_encode($req_id);

            syslog(LOG_INFO, 'OIDC Authorization Endpoint Proxy Redirect Location: ' . $url);
            header('Location: '.$url);
    
    
        } catch(Exception $e) {
            syslog(LOG_INFO, 'OIDC Authorization Endpoint Proxy Redirect Error: ' . $e->getMessage);

            if($this->config['debug'] || $e->getMessage()=='invalid_redirect_uri') {
                http_response_code(400);
                echo "ERROR: ".$e->getMessage();
    
            } else {
                $return = $redirect_uri;
                if($return=='') $return = '/';
                if(strpos($return, '?')>-1) { $return.='&error='.$e->getMessage(); }
                else { $return.='?error='.$e->getMessage(); }
                $return.='&error_description='.$e->getMessage();
                $return.='&state='.$state;
                header('Location: '.$return);
            }
        }
    }

    function callback() {
        $referer = $_SERVER['HTTP_REFERER'];
        $origin = $this->config['spid-php-proxy']['origin'];

        if((substr($referer, 0, strlen($origin)) === $origin)) {

            $req_id         = base64_decode($_POST['state']);
            $auth_code      = $this->db->createAuthorizationCode($req_id);
            $request        = $this->db->getRequest($req_id);
            $client_id      = $request['client_id'];
            $redirect_uri   = $request['redirect_uri'];
            $state          = $request['state'];
            $userinfo       = $_POST;

            unset($userinfo['state']);
            $this->db->saveUserinfo($req_id, $userinfo);

            $return = $redirect_uri;
            if(strpos($redirect_uri, '?')>-1) $return.='&code='.$auth_code;
            else $return.='?code='.$auth_code;
            $return.='&state='.$state;

            syslog(LOG_INFO, 'OIDC Authorization Endpoint Response Location: ' . $return);
            header("Location: ".$return);

        } else {
            if($this->config['debug']) {
                echo "Invalid origin: ".$origin;
            }

            syslog(LOG_INFO, 'OIDC Authorization Endpoint Response Error: invalid origin' . $origin);
            http_response_code(404);
        }
    }
}
