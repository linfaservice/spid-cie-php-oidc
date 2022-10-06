<?php

class EndpointSessionEnd extends Endpoint {

    public $name = "Session End Endpoint";

    function __construct($config, $db) {
        parent::__construct($config, $db);
    }

    function process() {
        $id_token_hint = $_GET['id_token_hint'];
        $post_logout_redirect_uri = $_GET['post_logout_redirect_uri'];
        $state = $_GET['state'];
    
        if($id_token_hint) {
            $this->db->log("SESSION END", "id_token_hint: " . $id_token_hint);
            if($this->db->checkIdToken($id_token_hint)) {
                $request = $this->db->getRequestByIdToken($id_token_hint);
                $this->db->deleteRequest($request['req_id']);
                $this->db->log("SESSION END", "deleted request id: " . $request['req_id']);

            } else {
                http_response_code(400);
                if($this->config['debug']) {
                    echo "ERROR: id_token not valid";
                    $this->db->log("SESSION_END_ERR", "id_token not valid");
                } 
            }

        } else {
            $this->db->log("SESSION END", "id_token_hint not present");
            $client_id = null;
            $clients = $this->config['clients'];
            foreach($clients as $id=>$client_config) {
                if(in_array($post_logout_redirect_uri, $client_config['post_logout_redirect_uri'])) {
                    $client_id = $id;
                    break;
                }
            }

            if($client_id!=null) {
                $request = $this->db->getRequestByClientID($client_id);
                foreach($request as $r) {
                    $req_id = $r['req_id'];
                    $this->db->deleteRequest($req_id);
                }

            } else {
                http_response_code(400);
                if($this->config['debug']) {
                    echo "ERROR: client_id not found for post_logout_redirect_uri";
                    $this->db->log("SESSION_END_ERR", "client_id not found for post_logout_redirect_uri");
                } 
            }
        }

        $this->db->log("SESSION END", "post_logout_redirect_uri: " . $post_logout_redirect_uri);
        $logout_url = $this->config['spid-php-proxy']['logout_url'];
        $logout_url.= '?client_id='.$this->config['spid-php-proxy']['client_id'];
        $logout_url.= '&redirect_uri='.urlencode($post_logout_redirect_uri);
        $logout_url.= '&state='.$state;
        header('Location: '.$logout_url); 
    }
}