<?php

    require("../lib/Database.php");
    require("../lib/Endpoint.php");
    require("../lib/EndpointAuthentication.php");
    require("../lib/EndpointToken.php");
    require("../lib/EndpointUserinfo.php");
    require("../lib/EndpointSessionEnd.php");

    const CONFIG_FILE = "../spid-php-oidc.json";

    $config         = file_exists(CONFIG_FILE)? json_decode(file_get_contents(CONFIG_FILE), true) : array();
    $db             = new Database($config['database']);

    $request_uri    = $_SERVER['REQUEST_URI'];
    $request        = parse_url($request_uri);
    $path           = $request['path'];
    $query          = $request['query'];

    parse_str($query, $params);

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
    }

    if($handler) {
        $handler->$function();
    } else {
        echo $path;
    }