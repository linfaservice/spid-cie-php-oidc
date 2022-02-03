<?php

require_once('JWT.php');

class EndpointCerts extends Endpoint {

    public $name = "Certs Endpoint";

    function __construct($config, $db) {
        parent::__construct($config, $db);
    }

    function process() {

        try {

            $jwk_pem = $this->config['jwt_public_cert'];
            $jwk = JWT::getCertificateJWK($jwk_pem);

            // fix \n json_encode issue
            $x5c    = $jwk->get('x5c')[0];
            $x5c    = preg_replace("/\s+/", "", $x5c);

            $cert = array(
                'kty'       => $jwk->get('kty'),
                'n'         => $jwk->get('n'),
                'e'         => $jwk->get('e'),
                'x5c'       => $x5c,
                'x5t'       => $jwk->get('x5t'),
                'x5t#256'   => $jwk->get('x5t#256'),
                'use'       => $jwk->get('use')
            );

            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($cert);
    
        } catch(Exception $e) {
            http_response_code(400);
            if($this->config['debug']) {
                echo "ERROR: ".$e->getMessage();
                $this->db->log("CERTS_ERR", $e->getMessage());
            } 
        }
    }

}