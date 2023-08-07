<?php

/*
 * Authenticator (https://github.com/alantiller/authenticator)
 * Copyright (c) Alan Tiller (https://www.alantiller.com/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace AlanTiller;

/** Component that provides all features and utilities for secure authentication of individual users */
final class Authenticator extends DatabaseManager {

    /**
	 * @param PdoDatabase|PdoDsn|\PDO $databaseConnection the database connection to operate on
	 */
    public function __construct($databaseConnection) {
		parent::__construct($databaseConnection);

        parent::checktables();
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
