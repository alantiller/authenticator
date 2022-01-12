<?php

/*
 * Slations Authenticator Class
 *
 * The library adds a simple and lightweight authentication class using medoo for database connectivity
 *
 * @copyright Copyright (c) 2021 Alan Tiller & Slations <alan@slations.co.uk>
 * @license GNU
 *
 */

namespace Slations;

class Authenticator {
    // Set the connection value
    protected static $connection;

    // Construct
    public function __construct($connection) {
		self::$connection = $connection;
	}


    /*
     * Auth Functions
     */

    // Authentication a user
    public static function user_auth($email, $password) {
        // Filter strings for SQL Injection
        $email = Utilities::string_filter($email);
        $password = Utilities::string_filter($password);
        
        $row_user = self::$connection->query('SELECT * FROM `slations_users` WHERE email = ?', $email)->fetchArray();

        $salted_hash = hash('sha256', $password . $row_user['salt']);
        if ($row_user['password'] != $salted_hash) {
            return array("status" => 400, "data" => array("error" => array("code" => "INVALID_CREDENTIALS", "message" => "Your email/password is incorrect.")));
        }

        if ($row_user['approved'] != '1') {
            return array("status" => 400, "data" => array("error" => array("code" => "ACCOUNT_NOT_ACTIVE", "message" => "Your account has not been activated yet.")));
        }

        if ($row_user['locked'] != '0') {
            return array("status" => 400, "data" => array("error" => array("code" => "ACCOUNT_LOCKED", "message" => "Your account has been locked by an administrator.")));
        }

        if ($row_user['verified'] != '1') {
            self::user_send_confirmation($row_user['email'], $row_user['id']);
            return array("status" => 400, "data" => array("error" => array("code" => "ACCOUNT_NOT_VERIFIED", "message" => "Your email has not been verified yet. Another email has been sent.")));
        }

        $user = $row_user['id'];
        $auth_token = Utilities::generate_random_string(30);
        $sql_timestamp = date("Y-m-d H:i:s"); 

        self::$connection->query("INSERT INTO `slations_tokens` (`id`, `user`, `service`, `timestamp`) VALUES (?, ?, ?, ?)", array($auth_token, $user, 'slations_users', $sql_timestamp));
        return array("status" => 200, "data" => array("token" => $auth_token, "user" => $user, "expiry" => $sql_timestamp));
    }

    // Log out a user
    public static function user_logout($token = null) {
        // If the token is not set this is a call from the app
        if ($token == null) {
            return array("status" => 400, "data" => array("error" => array("code" => "TOKEN_MISSING", "message" => "The token was not included in the request.")));
        }

        // Get all tokens matching the prodived in the user service
        $tokens = self::$connection->query("SELECT * FROM `slations_tokens` WHERE `id` = ? AND `service` = 'slations_users'", self::get_value('token'));

        // Check if the token exists
        if ($tokens->numRows() != 1) {
            return array("status" => 400, "data" => array("error" => array("code" => "TOKEN_INVALID", "message" => "The token provided was not found in the database.")));
        }

        // Execute query to remove token from database
        self::$connection->query("DELETE FROM `slations_tokens` WHERE `id` = ? AND `service` = 'slations_users'", $token);
        return array("status" => 204);
    }

    // Check the user to check if there logged in
    public static function user_check($token = null) {
        if ($token == null) {
            return array("status" => 400, "data" => array("error" => array("code" => "TOKEN_MISSING", "message" => "The token was not included in the request.")));
        }

        // Get all tokens matching the prodived in the user service
        $tokens = self::$connection->query("SELECT * FROM `slations_tokens` WHERE `id` = ? AND `service` = 'slations_users'", $token);

        // Check if the token exists
        if ($tokens->numRows() != 1) {
            return array("status" => 400, "data" => array("error" => array("code" => "TOKEN_INVALID", "message" => "The token provided was not found in the database.")));
        }

        $row_token = $tokens->fetchArray();
        $chktime = strtotime($row_token['timestamp']);
        $timenow = time();
        $time_diff = $timenow - $chktime;

        if ($time_diff > 1800) {
            return array("status" => 400, "data" => array("error" => array("code" => "SESSION_TIMEOUT", "message" => "The user session has timed out.")));
        }

        $sql_timestamp = date("Y-m-d H:i:s");
        self::$connection->query("UPDATE `slations_tokens` SET `timestamp` = ? WHERE `id` = ? AND `service` = 'slations_users'", array($sql_timestamp, $token));
        return array("status" => 204);
    }


    /*
     * User Functions
     */

    // Create user
    public static function user_create($first_name, $last_name, $email, $password) {
        // Filter strings for SQL Injection
        $first_name = Utilities::string_filter($first_name);
        $last_name = Utilities::string_filter($last_name);
        $email = Utilities::string_filter($email);
        $password = Utilities::string_filter($password);

        // Get any users with the same email address
        $users = self::$connection->query("SELECT * FROM `slations_users` WHERE email = ?", $email);

        // Check if there are any users with that email and respond with failure 
        if ($users->numRows() > 0) {
            return '<div class="alert error">Sorry! This email has already been registered!</div>';
        }
        
        $id = Utilities::uuid_v4();
        $password_salt = Utilities::generate_random_string(20);

        $salted_hash = hash('sha256', $password . $password_salt);

        $sql_timestamp = date("Y-m-d H:i:s");
        self::$connection->query("INSERT INTO `slations_users` (id, first_name, last_name, email, password, salt, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)", array($id, $first_name, $last_name, $email, $salted_hash, $password_salt, $sql_timestamp));

        // Generate UUID and send an email to confirm an account
        self::user_send_confirmation($email, $id);

        return '<div class="alert success">Success! Once you confirm your email address you\'ll be able to login to your account.</div>';
    }
    
    // Send confirmation email
    private static function user_send_confirmation($email, $user_id) {
        global $dotenv;
        
        $confirm_token = Utilities::uuid_v4();
        $sql_timestamp = date("Y-m-d H:i:s");

        self::$connection->query("INSERT INTO `slations_tokens` (`id`, `user_id`, `service`, `timestamp`) VALUES (?, ?, ?, ?)", array($confirm_token, $user_id, 'account_activation', $sql_timestamp));

        $body = file_get_contents('templates/email.confirm_email.html');

        $body = str_replace('{{project_name}}', application_name, $body);
        $body = str_replace('{{project_root}}', application_root, $body);
        $body = str_replace('{{token}}', $confirm_token, $body);

        mail($email, application_name . " - Confim your email address", $body, "MIME-Version: 1.0" . "\r\n" . "Content-type:text/html;charset=UTF-8" . "\r\n" . "From: ".application_name."<".$dotenv->read('EMAIL_FROM').">");
    }

    // Confirm the user email
    public static function user_confirm_email($token) {
        $tokens = self::$connection->query("SELECT * FROM `slations_tokens` WHERE `id` = ? AND `service` = 'account_activation'", Utilities::string_filter($token));

        if ($tokens->numRows() != 1) {
            return false;
        }
        
        $row_token = $tokens->fetchArray();
        $chktime = strtotime($row_token['timestamp']);
        $timenow = time();
        $time_diff = $timenow - $chktime;

        self::$connection->query("DELETE FROM `slations_tokens` WHERE `id` = ?", Utilities::string_filter($token));

        if ($time_diff > 2628000) {
            return false;
        }

        self::$connection->query("UPDATE `slations_users` SET `verified` = '1' WHERE id = ?", $row_token['user_id']);
        return true;
    }

    // Get a user by their ID
    public static function user_get($user_id) {
        return self::$connection->query("SELECT * FROM `slations_users` WHERE `id` = ?", $user_id)->fetchArray();
    }

    // Get the current user
    public static function user_get_me($token = null) {
        if ($token == null) {
            return array("status" => 400, "data" => array("error" => array("code" => "TOKEN_MISSING", "message" => "The token was not included in the request.")));
        }

        // Gets the user id from the token
        $user = self::$connection->query("SELECT * FROM `slations_tokens` WHERE `id` = ?", $token)->fetchArray()['user'];
        
        // Return the user result
        return self::user_get($user);
    }


    /*
     * Server Functions
     */

    public static function server_health() {
        
    }
}