<?php
    $Database = require("../../../lib/Database.php");

    const CONFIG_FILE = "../../../spid-php-oidc.json";
    const DEBUG = true;

    $config         = file_exists(CONFIG_FILE)? json_decode(file_get_contents(CONFIG_FILE), true) : array();
    $clients        = $config['clients'];
    $db             = new Database($config['database']);

    $id_token_hint = $_GET['id_token_hint'];
    $post_logout_redirect_uri = $_GET['post_logout_redirect_uri'];

    if($db->checkIdToken($id_token_hint)) {
        $request = $db->getRequestByIdToken($id_token_hint);
        $db->deleteRequest($request['req_id']);
        
        $logout_url = $config['spid-php-proxy']['logout_url'];
        $logout_url.= '?client_id='.$config['spid-php-proxy']['client_id'];
        $logout_url.= '&redirect_uri='.$config['spid-php-proxy']['post_logout_redirect_uri'];

        header('Location: '.$logout_url); 
    }
 