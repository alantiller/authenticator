<?php

/*
 * Authenticator Class
 *
 * The library adds a simple and lightweight authentication class using medoo for database connectivity
 *
 * @copyright Copyright (c) 2021 Alan Tiller <alan@slations.co.uk>
 * @license GNU
 *
 */

namespace AlanTiller;

use \Exception as Exception;

final class Authenticator extends DatabaseManager {

    /**
	 * @param PdoDatabase|PdoDsn|\PDO $databaseConnection the database connection to operate on
	 */
    public function __construct($databaseConnection) {
		parent::__construct($databaseConnection);
	}


    /* Auth */
    public function session()
    {
        return new SessionManager($this->databaseConnection);
    }

    /* User */
    public function user() 
    {
        return new UserManager($this->databaseConnection);
    }




    // Authentication a user
    public function user_auth($email, $password) {
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
    public function user_logout($token = null) {
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
    public function user_check($token = null) {
        try {
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

    

    // Send confirmation email
    private function user_send_confirmation($user_id) {
        $users = self::$database->select('users', '*', ['id' => $user_id]);

        if (count($users) != 1) { 
            throw new Exception('The user provided does not exist');
        }
        $user = $users[0];

        $confirm_token = \Ramsey\Uuid\Uuid::uuid4()->toString();
        
        self::$database->insert("tokens", [
            "id" => $confirm_token,
            "user" => $user['id'],
            "service" => "account_activation",
            "timestamp" => date("Y-m-d H:i:s")
        ]);

        $url_token = self::$confirm_email_url . '?token=' . $confirm_token;
        $body = self::template_confirm_email($url_token);

        // decide to send with php mail or mailer class
        mail($user['email'], "Confim your email address", $body, "MIME-Version: 1.0" . "\r\n" . "Content-type:text/html;charset=UTF-8" . "\r\n" . "From: " . self::$mailer_from);
    
        return true;
    }

    // Confirm the user email
    public function user_confirm_email($token) {
        $tokens = self::$database->select('tokens', '*', ['id' => $token, 'service' => 'account_activation']);

        if (count($tokens) != 1) { 
            throw new Exception('The token provided was not found in the database');
        }
        $token = $tokens[0];

        $chktime = strtotime($token['timestamp']);
        $timenow = time();
        $time_diff = $timenow - $chktime;

        self::$database->delete("tokens", ['id' => $token]);

        if ($time_diff > 2628000) {
            throw new Exception('The token has expired please try and login to get another verification request sent');
        }

        self::$database->update("users", ['verified' => '1'], ['id' => $token['user']]);
        return true;
    }
}
