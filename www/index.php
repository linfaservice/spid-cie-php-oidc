<?php

    require("../lib/Database.php");
    require("../lib/Endpoint.php");
    require("../lib/EndpointAuthentication.php");
    require("../lib/EndpointCerts.php");
    require("../lib/EndpointToken.php");
    require("../lib/EndpointUserinfo.php");
    require("../lib/EndpointSessionEnd.php");

    const SETUP_CONFIG_FILE = "../spid-php-oidc-setup.json";
    const CONFIG_FILE = "../spid-php-oidc.json";

    $setup_config = file_exists(SETUP_CONFIG_FILE)? json_decode(file_get_contents(SETUP_CONFIG_FILE), true) : array();
    $config = file_exists(CONFIG_FILE)? json_decode(file_get_contents(CONFIG_FILE), true) : array();

    if($setup_config['config_from_database']) {
        $db_config_file = json_decode(file_get_contents('../database-config.json'), true);
        $db_config = new PDO ($db_config_file['dsn'], $db_config_file['username'], $db_config_file['password']);
        $getConfig = $db_config->prepare("SELECT oidc FROM spid_cie_php_config");
        $getConfig->execute();
        $config = json_decode($getConfig->fetch()['oidc'], true);

        $db = Database::getDatabase($db_config_file, 'mysql');
    
    } else {

        $db = Database::getDatabase($config['database'], 'sqlite');
    }

    $request_uri    = $_SERVER['REQUEST_URI'] ?? '';
    $request        = parse_url($request_uri) ?? '';
    $path           = $request['path'] ?? '';
    $query          = $request['query'] ?? '';

    parse_str($query, $params);

    $db->log("OIDC", $path);

    $ip = $_SERVER['REMOTE_ADDR'];

    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }

    syslog(LOG_INFO, 'OIDC Request: ' . json_encode(array(
        'ip' => $ip,
        'path' => $path,
        'query'=> $query,
        'body' => $_POST
    )));

    switch($path) {
        case "/oidc/auth":          
            $handler = new EndpointAuthentication($config, $db); 
            $function = "process";
            break;
        case "/oidc/auth/proxy-callback.php":          
            $handler = new EndpointAuthentication($config, $db); 
            $function = "callback";
            break;
        case "/oidc/token":
            $handler = new EndpointToken($config, $db); 
            $function = "process";
            break;
        case "/oidc/userinfo":      
            $handler = new EndpointUserinfo($config, $db); 
            $function = "process";
            break;
        case "/oidc/session/end":   
            $handler = new EndpointSessionEnd($config, $db); 
            $function = "process";
            break;
        case "/oidc/certs":
            $handler = new EndpointCerts($config, $db); 
            $function = "process";
            break;
    }

    if($handler) {
        $handler->$function();
    } else {
        http_response_code(404);
        echo "404 Not Found";
    }