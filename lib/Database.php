<?php

include "DatabaseSQLite.php";
include "DatabaseMySQL.php";

abstract class Database {

    public static function getDatabase($config, $driver='sqlite') {

        switch($driver) {
            case 'sqlite': 
                return new DatabaseSQLite($config);
                break;

            case 'mysql': 
                return new DatabaseMySQL($config);
                break;

            default:
                return new DatabaseSQLite($config);
                break;
        }
    }

    abstract function createRequest($client_id, $redirect_uri, $state='', $nonce='');

    abstract function updateRequest($client_id, $redirect_uri, $state='', $nonce='');

    abstract function getRequest($req_id);

    abstract function getRequestByCode($code);

    abstract function getRequestByIdToken($id_token);

    abstract function getRequestByClientID($client_id);

    abstract function createAuthorizationCode($req_id);

    abstract function checkAuthorizationCode($client_id, $redirect_uri, $code);

    abstract function saveIdToken($req_id, $id_token);

    abstract function checkIdToken($id_token);

    abstract function createAccessToken($code);

    abstract function saveAccessToken($req_id, $access_token);

    abstract function checkAccessToken($access_token);

    abstract function saveUserinfo($req_id, $userinfo);

    abstract function getUserinfo($access_token);

    abstract function deleteRequest($req_id);

    abstract function query($sql, $values=array());

    abstract function exec($sql, $values=array());

    abstract function dump($table);

    abstract function log($tag, $value);
}