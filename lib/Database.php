<?php

class Database {

    function __construct($db_file) {
        $this->db = new SQLite3($db_file);
        if(!$this->db) { die("Error while connecting to db.sqlite"); }

        $this->db->exec("
            CREATE TABLE IF NOT EXISTS token (
                req_id          INTEGER PRIMARY KEY AUTOINCREMENT,
                req_timestamp   DATETIME DEFAULT (datetime('now')) NOT NULL,
                client_id       STRING NOT NULL,
                redirect_uri    STRING NOT NULL,
                code            STRING UNIQUE,
                auth_timestamp  DATETIME,
                access_token    STRING UNIQUE,
                token_timestamp DATETIME,
                state           STRING,
                userinfo        STRING
            );

            CREATE TABLE IF NOT EXISTS log (
                timestamp       DATETIME DEFAULT (datetime('now')) NOT NULL,
                tag             STRING,
                value           STRING
            );
        ");

        $this->db->exec("
            DELETE FROM token WHERE req_timestamp <= datetime('now', '-30 minutes');
            DELETE FROM log WHERE timestamp <= datetime('now', '-60 minutes');
        ");
    }

    function createRequest($client_id, $redirect_uri, $state='') {
        $code = uniqid();
        $stmt = $this->db->prepare("
            INSERT INTO token(client_id, redirect_uri, state) 
            VALUES(:client_id, :redirect_uri, :state);
        ");
        $stmt->bindValue(':client_id', $client_id, SQLITE3_TEXT);
        $stmt->bindValue(':redirect_uri', $redirect_uri, SQLITE3_TEXT);
        $stmt->bindValue(':state', $state, SQLITE3_TEXT);
        $stmt->execute();
        $req_id = $this->db->lastInsertRowid();
        return $req_id;
    }

    function updateRequest($client_id, $redirect_uri, $state='') {
        $req_id = null;
        $result = $this->query("
            SELECT req_id FROM token 
            WHERE client_id=:client_id 
            AND redirect_uri=:redirect_uri
            AND req_timestamp > datetime('now', '-30 minutes')
            ORDER BY req_timestamp DESC
            LIMIT 1;
        ", array(
            ":client_id" => $client_id,
            ":redirect_uri" => $redirect_uri
        ));

        if(count($result)==1) {
            $req_id = $result[0]['req_id'];
            $stmt = $this->db->prepare("
                UPDATE token 
                SET state=:state
                WHERE req_id=:req_id;
            ");
            $stmt->bindValue(':state', $state, SQLITE3_TEXT);
            $stmt->bindValue(':req_id', $req_id, SQLITE3_TEXT);
            $stmt->execute();
        }
        return $req_id;
    }

    function createAuthorizationCode($req_id) {
        $code = uniqid();
        $stmt = $this->db->prepare("
            UPDATE token 
            SET code=:code, auth_timestamp=datetime('now')
            WHERE req_id=:req_id;
        ");
        $stmt->bindValue(':code', $code, SQLITE3_TEXT);
        $stmt->bindValue(':req_id', $req_id, SQLITE3_TEXT);
        $stmt->execute();
        return $code;
    }

    function getRequest($req_id) {
        $result = $this->query("
            SELECT client_id, redirect_uri, state FROM token
            WHERE req_id = :req_id;",
            array(":req_id" => $req_id)
        );

        return array(
            "client_id"     => $result[0]['client_id'],
            "redirect_uri"  => $result[0]['redirect_uri'],
            "state"         => $result[0]['state'],
        );
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

    function createAccessToken($code) {
        $access_token = uniqid();
        $stmt = $this->db->prepare("
            UPDATE token
            SET access_token=:access_token, token_timestamp=datetime('now')
            WHERE code=:code;
        ");
        $stmt->bindValue(':access_token', $access_token, SQLITE3_TEXT);
        $stmt->bindValue(':code', $code, SQLITE3_TEXT);
        $stmt->execute();
        return $access_token;
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

    function query($sql, $values=array()) {
        $result = array();
        $stmt = $this->db->prepare($sql);
        foreach($values as $key=>$value) {
            $stmt->bindValue($key, $value, SQLITE3_TEXT);
        }
        $query = $stmt->execute();
        while($row = $query->fetchArray(SQLITE3_ASSOC)) {
            $result[] = $row;
        }
        return $result;
    }

    function exec($sql, $values=array()) {
        $stmt = $this->db->prepare($sql);
        foreach($values as $key=>$value) {
            $stmt->bindValue($key, $value, SQLITE3_TEXT);
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