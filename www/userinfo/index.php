<?php
    $Database = require("../../lib/Database.php");

    const CONFIG_FILE = "../../spid-php-oidc.json";
    const DEBUG = true;

    $config         = file_exists(CONFIG_FILE)? json_decode(file_get_contents(CONFIG_FILE), true) : array();
    $clients        = $config['clients'];
    $db             = new Database($config['database']);

    $db->log("USERINFO", "Bearer: ".getBearerToken());
    $userinfo = (array) $db->getUserinfo(getBearerToken());
    $userinfo['sub'] = $userinfo['fiscalNumber'];
    $db->log("USERINFO", $userinfo);

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($userinfo);

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
        return $headers;
    }
    /**
     * get access token from header
     * */
    function getBearerToken() {
        $headers = getAuthorizationHeader();
        // HEADER: Get the access token from the header
        if (!empty($headers)) {
            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
                return $matches[1];
            }
        }
        return null;
    }