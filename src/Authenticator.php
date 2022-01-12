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
    protected static $database;
    protected static $mailer;
    private static $mailer_from;

    // Construct
    public function __construct($db, $mailer, $mailer_from) {
		self::$database = $db;
        self::$mailer = $mailer;
        self::$mailer_from = $mailer_from;
	}


    /*
     * Auth Functions
     */

    // Authentication a user
    public static function user_auth($email, $password) {
        try {
            $users = self::$database->select('users', '*', ['email' => $email]);

            if (count($users) != 1) { 
                throw new Exception('The email address or password was incorrect');
            }
    
            $user = $users[0];
            $salted_hash = hash('sha256', $password . $user['salt']);
            
            if ($user['password'] != $salted_hash) {
                throw new Exception('The email address or password was incorrect');
            }
    
            if ($user['approved'] != '1') {
                throw new Exception('The account has not been activated');
            }
    
            if ($user['locked'] != '0') {
                throw new Exception('The account has been locked');
            }
    
            if ($user['verified'] != '1') {
                self::user_send_confirmation($user['email'], $user['id']);
                throw new Exception('The accounts email address has not been verified, another email was sent');
            }
    
            $auth_token = (new \Tokenly\TokenGenerator\TokenGenerator())->generateToken(30);
            self::$database->insert("tokens", [
                "id" => $auth_token,
                "user" => $user['id'],
                "service" => "authenticator",
                "timestamp" => date("Y-m-d H:i:s")
            ]);
    
            return array("result" => "success", "token" => $auth_token, "user" => $user['id']);
        } catch(Exception $error) {
            error_log($error->getMessage(), 0);
            return array("result" => "failed", "message" => $error->getMessage());
        }
    }

    // Log out a user
    public static function user_logout($token = null) {
        try {
            // If the token is not set this is a call from the app
            if ($token == null) {
                throw new Exception("The token was not included in the request");
            }

            // Get all tokens matching the prodived in the user service
            $tokens = self::$database->select('tokens', '*', ['id' => $token, 'service' => 'authenticator'])[0];
            
            // Check if the token exists
            if (count($tokens) != 1) {
                throw new Exception("The token provided was not found in the database");
            }
            $token = $tokens[0];

            // Execute query to remove token from database
            self::$database->delete('tokens', [
                'AND' => [
                    'id' => $token['id'],
                    'service' => 'authenticator'
                ]
            ]);
            return array("status" => "success");
        } catch (Exception $error) {
            error_log($error->getMessage(), 0);
            return array("status" => "failed", "message" => $error->getMessage());
        }
    }

    // Check the user to check if there logged in
    public static function user_check($token = null) {
        try {
            if ($token == null) {
                throw new Exception("The token was not included in the request");
            }
    
            // Get all tokens matching the prodived in the user service
            $tokens = self::$connection->query("SELECT * FROM `slations_tokens` WHERE `id` = ? AND `service` = 'slations_users'", $token);
    
            // Check if the token exists
            if ($tokens->numRows() != 1) {
                throw new Exception("The token provided was not found in the database");
            }
            $token = $tokens[0];
    
            $chktime = strtotime($token['timestamp']);
            $timenow = time();
            $time_diff = $timenow - $chktime;
    
            if ($time_diff > 1800) {
                throw new Exception("The user session has timed out");
            }
    
            self::$database->update("account", ["timestamp" => date("Y-m-d H:i:s")], ["id" => $token['id']]);
       
            return array("status" => "success");
        } catch (Exception $error) {
            error_log($error->getMessage(), 0);
            return array("status" => "failed", "message" => $error->getMessage());
        }
    }


    /*
     * User Functions
     */

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


    /*
     * Confirm Email Functions
     */

    // Send confirmation email
    private static function user_send_confirmation($user_id) {
        $users = self::$database->select('users', '*', ['id' => $user_id]);

        if (count($users) != 1) { 
            throw new Exception('The email address or password was incorrect');
        }
        $user = $users[0];

        $confirm_token = Ramsey\Uuid\Uuid::uuid4()->toString();
        
        self::$database->insert("tokens", [
            "id" => $confirm_token,
            "user" => $user['id'],
            "service" => "account_activation",
            "timestamp" => date("Y-m-d H:i:s")
        ]);

        $body = file_get_contents('templates/email.confirm_email.html');

        $body = str_replace('{{project_name}}', application_name, $body);
        $body = str_replace('{{project_root}}', application_root, $body);
        $body = str_replace('{{token}}', $confirm_token, $body);

        $email = (new Email())->from(self::$mailer_from)->to($user['email'])->subject('Confim your email address')->html($body);
        self::$mailer->send($email);
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
}