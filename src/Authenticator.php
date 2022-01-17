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

use \Exception as Exception;

class Authenticator {
    // Set the connection value
    protected static $database;
    protected static $env_key;
    protected static $mailer;
    private static $confirm_email_url;
    private static $mailer_from;

    // Construct
    public function __construct($db, $mailer_from, $confirm_email_url, $env_key = '', $mailer = null) {
		self::$database = $db;
        self::$env_key = $env_key;
        self::$mailer = $confirm_email_url;
        self::$confirm_email_url = $mailer;
        self::$mailer_from = $mailer_from;
	}

    // Authentication a user
    public static function user_auth($email, $password) {
        try {
            $users = self::$database->select('users', '*', ['email' => $email]);

            if (count($users) != 1) { 
                throw new Exception('The email address or password was incorrect');
            }
    
            $user = $users[0];
            $salted_hash = hash('sha256', $env_key . $password . $user['salt']);
            
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
                self::user_send_confirmation($user['id']);
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
            $tokens = self::$database->select('tokens', '*', ['id' => $token, 'service' => 'authenticator']);
            
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
            $tokens = self::$database->select('tokens', '*', ['id' => $token, 'service' => 'authenticator'])[0];
    
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

    // Get a user by their ID
    public static function user_get($user_id) {    
        try {
            $users = self::$database->select('users', '*', ['id' => $user_id]);
        
            if (count($users) != 1) { 
                throw new Exception('The user does not exist');
            }

            return $users[0];
        } catch (Exception $error) {
            error_log($error->getMessage(), 0);
            return array("status" => "failed", "message" => $error->getMessage());
        }
    }

    // Get the current user
    public static function user_get_me($token = null) {
        try {
            if ($token == null) {
                throw new Exception("The token was not included in the request");
            }

            $tokens = self::$database->select('tokens', '*', ['id' => $token, 'service' => 'authenticator']);
        
            // Check if the token exists
            if (count($tokens) != 1) { 
                throw new Exception('The token sent does not exist');
            }
            $token = $tokens[0];

            // Return the user result
            return self::user_get($token['id']);
        } catch (Exception $error) {
            error_log($error->getMessage(), 0);
            return array("status" => "failed", "message" => $error->getMessage());
        }
    }

    // Create user
    public static function user_create($name, $email, $password) {
        try {
            // Check if the email address already exists
            $users = self::$database->select('users', '*', ['email' => $email]);

            if (count($users) > 0) { 
                throw new Exception('The email address already exists');
            }

            // Generate the users account id and salt
            $id = \Ramsey\Uuid\Uuid::uuid4()->toString();
            $password_salt = (new \Tokenly\TokenGenerator\TokenGenerator())->generateToken(20);

            // Hash the users password
            $salted_hash = hash('sha256', $env_key . $password . $password_salt);

            // Create the account
            self::$database->insert("users", [
                "id" => $id,
                "name" => $name,
                "email" => $email,
                "password" => $salted_hash,
                "salt" => $password_salt,
                "timestamp" => date("Y-m-d H:i:s")
            ]);

            // Generate UUID and send an email to confirm an account
            self::user_send_confirmation($id);

            return array("status" => "success");
        } catch (Exception $error) {
            error_log($error->getMessage(), 0);
            return array("status" => "failed", "message" => $error->getMessage());
        }
    }

    // Send confirmation email
    private static function user_send_confirmation($user_id, $url) {
        $users = self::$database->select('users', '*', ['id' => $user_id]);

        if (count($users) != 1) { 
            throw new Exception('The email address or password was incorrect');
        }
        $user = $users[0];

        $confirm_token = \Ramsey\Uuid\Uuid::uuid4()->toString();
        
        self::$database->insert("tokens", [
            "id" => $confirm_token,
            "user" => $user['id'],
            "service" => "account_activation",
            "timestamp" => date("Y-m-d H:i:s")
        ]);

        $url_token = $url . '?token=' . $confirm_token;
        $body = self::template_confirm_email($url_token);

        // decide to send with php mail or mailer class
        mail($user['email'], "Confim your email address", $body, "MIME-Version: 1.0" . "\r\n" . "Content-type:text/html;charset=UTF-8" . "\r\n" . "From: " . self::$mailer_from);
    
        return true;
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


    // Template - Confirm Email
    private static function template_confirm_email($token) {
        $body;

        $body .= '<p>Hi there,</p>';
        $body .= '<p>Please click on the libk below to confirm your email address.</p>';
        $body .= '<a href="' . $token . '">Confirm Email Address</a>';
        $body .= '<p>Thanks for registering.</p>';

        return $body;
    }
}