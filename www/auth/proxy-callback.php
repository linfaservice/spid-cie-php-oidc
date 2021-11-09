<?php

$Database = require("../../lib/Database.php");

const CONFIG_FILE = "../../spid-php-oidc.json";
const DEBUG = true;

$config = file_exists(CONFIG_FILE)? json_decode(file_get_contents(CONFIG_FILE), true) : array();
$db = new Database($config['database']);
$origin = $_SERVER['HTTP_ORIGIN'];

if($origin==$config['spid-php-proxy']['origin']) {

    /*
    $spidCode       = $_POST['spidCode'];
    $name           = $_POST['name'];
    $familyName     = $_POST['familyName'];
    $placeOfBirth   = $_POST['placeOfBirth'];
    $countyOfBirth  = $_POST['countyOfBirth'];
    $dateOfBirth    = $_POST['dateOfBirth'];
    $gender         = $_POST['gender'];
    $fiscalNumber   = $_POST['fiscalNumber'];
    $mobilePhone    = $_POST['mobilePhone'];
    $email          = $_POST['email'];
    */

    $req_id         = base64_decode($_POST['state']);
    $auth_code      = $db->createAuthorizationCode($req_id);
    $request        = $db->getRequest($req_id);
    $client_id      = $request['client_id'];
    $redirect_uri   = $request['redirect_uri'];
    $state          = $request['state'];

    $return = $redirect_uri;
    if(strpos($redirect_uri, '?')>-1) $return.='&code='.$auth_code;
    else $return.='?code='.$auth_code;
    $return.='&state='.$state;

    header("Location: ".$return);

} else {
    if(DEBUG) {
        echo "Invalid origin: ".$origin;
    }
    http_response_code(404);
}
