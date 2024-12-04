<?php

class EndpointUserinfo extends Endpoint {

    public $name = "Userinfo Endpoint";

    function __construct($config, $db) {
        parent::__construct($config, $db);
    }

    function process() {
        try {
            $bearer = $this->getBearerToken();
            $this->db->log("USERINFO", "Bearer: ".$bearer);
            syslog(LOG_INFO, 'OIDC Userinfo Endpoint Request Bearer: ' . $bearer);
            if($bearer==null || $bearer=='') throw new Exception('access_denied');

            $userinfo = (array) $this->db->getUserinfo($bearer);
            $userinfo['sub'] = $userinfo['fiscalNumber'];
            if($userinfo['sub']==null) $userinfo['sub'] = $userinfo['spidCode'];
            $this->db->log("USERINFO", $userinfo);

            header('Content-Type: application/json; charset=utf-8');
            syslog(LOG_INFO, 'OIDC Userinfo Endpoint Response: ' . json_encode($userinfo));
            echo json_encode($userinfo);

        } catch(Exception $e) {
            http_response_code(400);
            if($this->config['debug']) {
                echo "ERROR: ".$e->getMessage();
                $this->db->log("USERINFO_ERR", $e->getMessage());
                syslog(LOG_INFO, 'OIDC Userinfo Endpoint Error: ' . $e->getMessage());
            } 
        }
    }

    /** 
     * Get hearder Authorization
     * */
    function getAuthorizationHeader(){
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
        $this->db->log("HEADERS", var_export($headers, true));
        return $headers;
    }
    /**
     * get access token from header
     * */
    function getBearerToken() {
        $headers = $this->getAuthorizationHeader();
        // HEADER: Get the access token from the header
        if (!empty($headers)) {
            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
                $this->db->log("BEARER", var_export($matches, true));
                return $matches[1];
            }
        }
        return null;
    }
}