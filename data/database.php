<?php

class Database {

    function __construct() {
        $this->db = new SQLite3("db.sqlite");
        if(!$this->db) { die("Error while connecting to db.sqlite"); }

        $this->db->exec("
            CREATE TABLE IF NOT EXISTS token (
                client_id       STRING NOT NULL,
                redirect_uri    STRING NOT NULL,
                code            STRING PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))) NOT NULL,
                auth_timestamp  DATETIME DEFAULT (datetime('now')) NOT NULL,
                access_token    STRING UNIQUE,
                token_timestamp DATETIME
            );
        ");

        $this->db->exec("
            DELETE FROM token WHERE auth_timestamp <= datetime('now', '-5 minutes');
        ");
    }

    function createAuthorizationCode($client_id, $redirect_uri) {
        $code = uniqid();
        $stmt = $this->db->prepare("
            INSERT INTO token(client_id, redirect_uri, code) VALUES(:client_id, :redirect_uri);
        ");
        $stmt->bindValue(':client_id', $client_id, SQLITE3_TEXT);
        $stmt->bindValue(':redirect_uri', $redirect_uri, SQLITE3_TEXT);
        $stmt->execute();
    }

    function checkAuthorizationCode($client_id, $redirect_uri, $code) {
        $check = false;
        $stmt = $this->db->prepare("
            SELECT * FROM token 
            WHERE client_id=:client_id 
            AND redirect_uri=:redirect_uri
            AND code=:code;
        ");
        $stmt->bindValue(':client_id', $client_id, SQLITE3_TEXT);
        $stmt->bindValue(':redirect_uri', $redirect_uri, SQLITE3_TEXT);
        $stmt->bindValue(':code', $code, SQLITE3_TEXT);
        $result = $stmt->execute();
        if(count($result)==1) $check = true;
        return $check;
    }

    function createAccessToken($code) {
        $access_token = uniqid();
        $stmt = $this->db->prepare("
            INSERT INTO token(access_token, token_timestamp) 
            VALUES(:access_token, datetime('now'))
            WHERE code=:code;
        ");
        $stmt->bindValue(':access_token', $access_token, SQLITE3_TEXT);
        $stmt->bindValue(':code', $code, SQLITE3_TEXT);
        $stmt->execute();
    }
    
}