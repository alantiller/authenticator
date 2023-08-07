<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace AlanTiller;

use Tokenly\TokenGenerator\TokenGenerator;
use PDO;
use Exception;
use PDOException;
use PDOStatement;
use InvalidArgumentException;


/**
 * Abstract base class for components implementing user management
 * @internal
 */

abstract class DatabaseManager {
	
	/** @var PdoDatabase the database connection to operate on */
	protected $db;

	/**
	 * @param PdoDatabase|PdoDsn|\PDO $databaseConnection the database connection to operate on
	 */
	protected function __construct($databaseConnection)
	{
		$this->db = $databaseConnection;
	}


	/**
     * Runs a select query
     *
     * @param string $table
	 * @param string $fields
	 * @param string $where
     * @return array
     */
	protected function select($table, $fields, $where)
	{
		// Execute the SQL query
		if (!$where)
		{
			$request = $this->databaseConnection->prepare("SELECT ? FROM ? WHERE ?");

			$request->execute($table, $fields, $where);
		}
		else
		{
			$request = $this->databaseConnection->prepare("SELECT ? FROM ?");

			$request->execute($table, $fields);
		}

		// return the results
		return $request->setFetchMode(PDO::FETCH_ASSOC);
	}


	/**
     * Runs a select query
     *
     * @param string $table
	 * @param string $fields
	 * @param string $where
     * @return array
     */
	protected function select($table, $fields, $where)
	{
		// Execute the SQL query
		if (!$where)
		{
			$request = $this->databaseConnection->prepare("SELECT ? FROM ? WHERE ?");

			$request->execute($table, $fields, $where);
		}
		else
		{
			$request = $this->databaseConnection->prepare("SELECT ? FROM ?");

			$request->execute($table, $fields);
		}

		// return the results
		return $request->setFetchMode(PDO::FETCH_ASSOC);
	}
}