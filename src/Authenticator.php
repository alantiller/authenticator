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
        return new SessionManager($this->db);
    }

    /* User */
    public function user() 
    {
        return new UserManager($this->db);
    }
}
