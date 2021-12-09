<?php

class EndpointSessionEnd extends Endpoint {

    public $name = "Session End Endpoint";

    function __construct($config, $db) {
        parent::__construct($config, $db);
    }

    function process() {
        $id_token_hint = $_GET['id_token_hint'];
        $post_logout_redirect_uri = $_GET['post_logout_redirect_uri'];
    
        if($this->db->checkIdToken($id_token_hint)) {
            $request = $this->db->getRequestByIdToken($id_token_hint);
            $this->db->deleteRequest($request['req_id']);
            
            $this->db->log("SESSION END", $post_logout_redirect_uri);

            $logout_url = $this->config['spid-php-proxy']['logout_url'];
            $logout_url.= '?client_id='.$this->config['spid-php-proxy']['client_id'];
            $logout_url.= '&redirect_uri='.urlencode($post_logout_redirect_uri);
    
            header('Location: '.$logout_url); 
        }
    }
}