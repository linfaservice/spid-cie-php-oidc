<?php 

    class Endpoint {

        function __construct($config, $db) {
            $this->config = $config;
            $this->db = $db;
        }
    }