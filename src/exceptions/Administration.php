<?php

namespace AlanTiller\Authenticator;

final class Administration extends UserManager {

	public function __construct($db) {
		parent::__construct($db);
	}

	public function createUser($email, $password, $name = null) {
		return $this->createUser($email, $password, $name, null);
	}

	public function changePassword($userId, $newPassword) {
		$userId = (int) $userId;
		$newPassword = self::validatePassword($newPassword);

		$this->updatePasswordInternal(
			$userId,
			$newPassword
		);

		$this->forceLogoutForUserById($userId);
	}

	public function deleteUser($id) {
		$numberOfDeletedUsers = $this->deleteUsersByColumnValue('id', (int) $id);

		if ($numberOfDeletedUsers === 0) {
			throw new UnknownIdException();
		}
	}

	public function loginAsUser($id) {
		$numberOfMatchedUsers = $this->logInAsUserByColumnValue('id', (int) $id);

		if ($numberOfMatchedUsers === 0) {
			throw new UnknownIdException();
		}
	}
}