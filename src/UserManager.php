<?php

/*
 * User Manager
 *
 * The library adds a simple and lightweight authentication class using medoo for database connectivity
 *
 * @copyright Copyright (c) 2021 Alan Tiller <alan@slations.co.uk>
 * @license GNU
 *
 */

namespace AlanTiller;

use \Exception;

final class UserManager extends DatabaseManager {

    /**
	 * @param PdoDatabase|PdoDsn|\PDO $databaseConnection the database connection to operate on
	 */
    public function __construct($databaseConnection) {
		parent::__construct($databaseConnection);
	}

    // Get a user by their ID
    public function get($user) 
    {    
        try {
            $users = $this->select('users', '*', 'id = ' . $user);
        
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
    public function me($token = null) {
        try {
            if ($token == null) {
                throw new Exception("The token was not included in the request");
            }

            $tokens = $this->select('tokens', '*', ['id' => $token, 'service' => 'authenticator']);
        
            // Check if the token exists
            if (count($tokens) != 1) { 
                throw new Exception('The token sent does not exist');
            }
            $token = $tokens[0];

            // Return the user result
            return self::get($token['user']);
        } catch (Exception $error) {
            error_log($error->getMessage(), 0);
            return array("status" => "failed", "message" => $error->getMessage());
        }
    }

    // Create user
    public function create($name, $email, $password) {
        try {
            // Check if the email address already exists
            $users = $this->select('users', '*', ['email' => $email]);

            if (count($users) > 0) { 
                throw new Exception('The email address already exists');
            }

            // Hash the users password
            $salted_hash = hash('sha256', $env_key . $password . $password_salt);

            // Create the account
            $this->insert("users", [
                "name" => $name,
                "email" => $email,
                "password" => $salted_hash,
                "timestamp" => date("Y-m-d H:i:s")
            ]);

            return array("status" => "success", "id" => $id);
        } catch (Exception $error) {
            error_log($error->getMessage(), 0);
            return array("status" => "failed", "message" => $error->getMessage());
        }
    }
}