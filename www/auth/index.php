<?php
    const CONFIG_FILE = "../../spid-php-oidc.json";
    const DEBUG = true;

    $config         = file_exists(CONFIG_FILE)? json_decode(file_get_contents(CONFIG_FILE), true) : array();
    $clients        = $config['clients'];

    $scope          = $_GET['scope'];
    $response_type  = $_GET['response_type'];
    $client_id      = $_GET['client_id'];
    $redirect_uri   = $_GET['redirect_uri'];
    $state          = $_GET['state'];

    try {
        if(strpos($scope, 'openid')<0) throw new Exception('invalid_scope');
        if(strpos($scope, 'profile')<0) throw new Exception('invalid_scope');
        if($response_type!='code') throw new Exception('invalid_request');
        if(!in_array($client_id, array_keys($clients))) throw new Exception('invalid_client');
        if(!in_array($redirect_uri, $clients[$client_id]['redirect_uri'])) throw new Exception('invalid_redirect_uri');

        header('Location: '.$config['spid-php-proxy']['url']
            .'?client_id='.$config['spid-php-proxy']['client_id']
            .'&level='.$config['clients'][$client_id]['level']
            .'&redirect_uri='.$config['spid-php-proxy']['redirect_uri']);

    } catch(Exception $e) {
        if(DEBUG) {
            echo "ERROR: ".$e->getMessage();

        } else {
            $return = $redirect_uri;
            if(strpos($return, '?')>-1) { $return.='&error='.$e->getMessage(); }
            else { $return.='?error='.$e->getCode(); }
            $return.='&error_description='.$e->getMessage();
            $return.='&state='.$state;
            header('Location: '.$return);
        }
    }