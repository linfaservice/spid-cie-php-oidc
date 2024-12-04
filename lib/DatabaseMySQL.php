<?php

class DatabaseMySQL extends Database {

    function __construct($config) {
        $this->db = new PDO ($config['dsn'], $config['username'], $config['password']);
        if(!$this->db) { die("Error while connecting to db"); }

        $this->db->exec("
            CREATE TABLE IF NOT EXISTS token (
                req_id          int NOT NULL AUTO_INCREMENT PRIMARY KEY,
                req_timestamp   datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
                client_id       tinytext NOT NULL,
                redirect_uri    text NOT NULL,
                code            tinytext UNIQUE,
                auth_timestamp  datetime,
                id_token        text UNIQUE,
                access_token    tinytext UNIQUE,
                token_timestamp datetime,
                state           text,
                userinfo        text,
                nonce           text
            );

            CREATE TABLE IF NOT EXISTS log (
                timestamp       datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
                tag             text,
                value           text
            );
        ");

        $this->db->exec("
            DELETE FROM token WHERE req_timestamp <= (NOW() - INTERVAL 30 MINUTE);
            DELETE FROM log WHERE timestamp <= (NOW() - INTERVAL 60 MINUTE);
        ");
    }

    function createRequest($client_id, $redirect_uri, $state='', $nonce='') {
        $code = uniqid();
        $stmt = $this->db->prepare("
            INSERT INTO token(client_id, redirect_uri, state, nonce) 
            VALUES(:client_id, :redirect_uri, :state, :nonce);
        ");
        $stmt->bindValue(':client_id', $client_id, PDO::PARAM_STR);
        $stmt->bindValue(':redirect_uri', $redirect_uri, PDO::PARAM_STR);
        $stmt->bindValue(':state', $state, PDO::PARAM_STR);
        $stmt->bindValue(':nonce', $nonce, PDO::PARAM_STR);
        $stmt->execute();
        //$req_id = $this->db->lastInsertRowid();
        $req_id = $this->db->lastInsertId();
        return $req_id;
    }

    function updateRequest($client_id, $redirect_uri, $state='', $nonce='') {
        $req_id = null;
        $result = $this->query("
            SELECT req_id FROM token 
            WHERE client_id=:client_id 
            AND redirect_uri=:redirect_uri
            AND nonce=:nonce
            AND req_timestamp > (NOW() - INTERVAL 30 MINUTE)
            ORDER BY req_timestamp DESC
            LIMIT 1;
        ", array(
            ":client_id" => $client_id,
            ":redirect_uri" => $redirect_uri,
            ":nonce" => $nonce
        ));

        if(count($result)==1) {
            $req_id = $result[0]['req_id'];
            $stmt = $this->db->prepare("
                UPDATE token 
                SET state=:state
                WHERE req_id=:req_id;
            ");
            $stmt->bindValue(':state', $state, PDO::PARAM_STR);
            $stmt->bindValue(':req_id', $req_id, PDO::PARAM_STR);
            $stmt->execute();
        }
        return $req_id;
    }

    function getRequest($req_id) {
        $result = $this->query("
            SELECT client_id, redirect_uri, state, nonce FROM token
            WHERE req_id = :req_id;",
            array(":req_id" => $req_id)
        );

        return array(
            "client_id"     => $result[0]['client_id'],
            "redirect_uri"  => $result[0]['redirect_uri'],
            "state"         => $result[0]['state'],
            "nonce"         => $result[0]['nonce'],
        );
    }

    function getRequestByCode($code) {
        $result = $this->query("
            SELECT req_id, client_id, redirect_uri, state, nonce FROM token
            WHERE code = :code;",
            array(":code" => $code)
        );

        return array(
            "req_id"        => $result[0]['req_id'],
            "client_id"     => $result[0]['client_id'],
            "redirect_uri"  => $result[0]['redirect_uri'],
            "state"         => $result[0]['state'],
            "nonce"         => $result[0]['nonce'],
        );
    }

    function getRequestByIdToken($id_token) {
        $result = $this->query("
            SELECT req_id, client_id, redirect_uri, state, nonce FROM token
            WHERE id_token = :id_token;",
            array(":id_token" => $id_token)
        );

        return array(
            "req_id"        => $result[0]['req_id'],
            "client_id"     => $result[0]['client_id'],
            "redirect_uri"  => $result[0]['redirect_uri'],
            "state"         => $result[0]['state'],
            "nonce"         => $result[0]['nonce'],
        );
    }

    function getRequestByClientID($client_id) {
        $result = $this->query("
            SELECT req_id, client_id, redirect_uri, state, nonce FROM token
            WHERE client_id = :client_id;",
            array(":client_id" => $client_id)
        );

        return $result;
    }

    function createAuthorizationCode($req_id) {
        $code = uniqid();
        $stmt = $this->db->prepare("
            UPDATE token 
            SET code=:code, auth_timestamp=NOW()
            WHERE req_id=:req_id;
        ");
        $stmt->bindValue(':code', $code, PDO::PARAM_STR);
        $stmt->bindValue(':req_id', $req_id, PDO::PARAM_STR);
        $stmt->execute();
        return $code;
    }

    function checkAuthorizationCode($client_id, $redirect_uri, $code) {
        $check = false;
        $result = $this->query("
            SELECT req_id FROM token 
            WHERE client_id=:client_id 
            AND redirect_uri=:redirect_uri
            AND code=:code;
        ", array(
            ":client_id" => $client_id,
            ":redirect_uri" => $redirect_uri,
            ":code" => $code
        ));

        if(count($result)==1) $check = true;
        return $check;
    }

    function saveIdToken($req_id, $id_token) {
        $this->exec(
            "UPDATE token SET id_token=:id_token WHERE req_id=:req_id", 
            array(
                ":id_token" => $id_token,
                ":req_id" => $req_id
            )
        );
    }

    function checkIdToken($id_token) {
        $check = false;
        $result = $this->query("
            SELECT req_id FROM token 
            WHERE id_token=:id_token;
        ", array(
            ":id_token" => $id_token
        ));

        if(count($result)==1) $check = true;
        return $check;
    }

    function createAccessToken($code) {
        $access_token = uniqid();
        $stmt = $this->db->prepare("
            UPDATE token
            SET access_token=:access_token, token_timestamp=NOW()
            WHERE code=:code;
        ");
        $stmt->bindValue(':access_token', $access_token, PDO::PARAM_STR);
        $stmt->bindValue(':code', $code, PDO::PARAM_STR);
        $stmt->execute();
        return $access_token;
    }

    function saveAccessToken($req_id, $access_token) {
        $this->exec(
            "UPDATE token SET access_token=:access_token WHERE req_id=:req_id", 
            array(
                ":access_token" => $access_token,
                ":req_id" => $req_id
            )
        );
    }

    function checkAccessToken($access_token) {
        $check = false;
        $result = $this->query("
            SELECT req_id FROM token 
            WHERE access_token=:access_token;
        ", array(
            ":access_token" => $access_token
        ));

        if(count($result)==1) $check = true;
        return $check;
    }

    function saveUserinfo($req_id, $userinfo) {
        $this->exec(
            "UPDATE token SET userinfo=:userinfo WHERE req_id=:req_id", 
            array(
                ":userinfo" => json_encode($userinfo),
                ":req_id" => $req_id
            )
        );
    }

    function getUserinfo($access_token) {
        $userinfo = $this->query(
            "SELECT userinfo FROM token WHERE access_token=:access_token",
            array(":access_token" => $access_token)
        );
        return json_decode($userinfo[0]['userinfo']);
    }

    function deleteRequest($req_id) {
        return $this->exec(
            "DELETE FROM token WHERE req_id=:req_id",
            array(":req_id" => $req_id)
        );
    }

    function query($sql, $values=array()) {
        $result = array();
        $stmt = $this->db->prepare($sql);

        error_log($sql);
        error_log(var_export($values, true));
        error_log(var_export($this->db->errorInfo(), true));
        die();

        $stmt->execute($values);
        foreach ($stmt as $row) {
            $result[] = $row;
        }
        return $result;
    }

    function exec($sql, $values=array()) {
        $stmt = $this->db->prepare($sql);
        foreach($values as $key=>$value) {
            $stmt->bindValue($key, $value, PDO::PARAM_STR);
        }
        $result = $stmt->execute();
        return $result;
    }

    function dump($table) {
        return $this->query("SELECT * FROM ".$table);
    }

    function log($tag, $value) {
        $this->exec("
            INSERT INTO log(tag, value)
            VALUES(:tag, :value);
        ", array(
            ":tag" => $tag,
            ":value" => json_encode($value)
        ));
    }
    
}