<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

use Delight\Base64\Base64;
use Delight\Cookie\Cookie;
use Delight\Cookie\Session;
use Delight\Db\PdoDatabase;
use Delight\Db\PdoDsn;
use Delight\Db\Throwable\Error;
use Delight\Db\Throwable\IntegrityConstraintViolationException;

/** Component that provides all features and utilities for secure authentication of individual users */
final class Auth extends UserManager {

	private $ipAddress;

	public function __construct($db, $ipAddress = null) {
		parent::__construct($db);
		$this->ipAddress = !empty($ipAddress) ? $ipAddress : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null);
	}

	/**
	 * Attempts to sign up a user
	 *
	 * If you want the user's account to be activated by default, pass `null` as the callback
	 *
	 * If you want to make the user verify their email address first, pass an anonymous function as the callback
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to verify their email address as a next step, both pieces will be required again
	 *
	 * @param string $email the email address to register
	 * @param string $password the password for the new account
	 * @param string|null $username (optional) the username that will be displayed
	 * @param callable|null $callback (optional) the function that sends the confirmation email to the user
	 * @return int the ID of the user that has been created (if any)
	 * @throws InvalidEmailException if the email address was invalid
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws UserAlreadyExistsException if a user with the specified email address already exists
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see confirmEmail
	 * @see confirmEmailAndSignIn
	 */
	public function register($email, $password, $username = null, callable $callback = null) {
		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);
		$this->throttle([ 'createNewAccount', $this->getIpAddress() ], 1, (60 * 60 * 12), 5, true);

		$newUserId = $this->createUserInternal(false, $email, $password, $username, $callback);

		$this->throttle([ 'createNewAccount', $this->getIpAddress() ], 1, (60 * 60 * 12), 5, false);

		return $newUserId;
	}

	/**
	 * Attempts to sign in a user with their email address and password
	 *
	 * @param string $email the user's email address
	 * @param string $password the user's password
	 * @param int|null $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
	 * @param callable|null $onBeforeSuccess (optional) a function that receives the user's ID as its single parameter and is executed before successful authentication; must return `true` to proceed or `false` to cancel
	 * @throws InvalidEmailException if the email address was invalid or could not be found
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
	 * @throws AttemptCancelledException if the attempt has been cancelled by the supplied callback that is executed before success
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function login($email, $password, $rememberDuration = null, callable $onBeforeSuccess = null) {
		$this->throttle([ 'attemptToLogin', 'email', $email ], 500, (60 * 60 * 24), null, true);

		$this->authenticateUserInternal($password, $email, null, $rememberDuration, $onBeforeSuccess);
	}

	/**
	 * Attempts to confirm the currently signed-in user's password again
	 *
	 * Whenever you want to confirm the user's identity again, e.g. before
	 * the user is allowed to perform some "dangerous" action, you should
	 * use this method to confirm that the user is who they claim to be.
	 *
	 * For example, when a user has been remembered by a long-lived cookie
	 * and thus {@see isRemembered} returns `true`, this means that the
	 * user has not entered their password for quite some time anymore.
	 *
	 * @param string $password the user's password
	 * @return bool whether the supplied password has been correct
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function reconfirmPassword($password) {
		if ($this->isLoggedIn()) {
			try {
				$password = self::validatePassword($password);
			}
			catch (InvalidPasswordException $e) {
				return false;
			}

			$this->throttle([ 'reconfirmPassword', $this->getIpAddress() ], 3, (60 * 60), 4, true);

			try {
				$expectedHash = $this->db->selectValue(
					'SELECT password FROM ' . $this->makeTableName('users') . ' WHERE id = ?',
					[ $this->getUserId() ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			if (!empty($expectedHash)) {
				$validated = \password_verify($password, $expectedHash);

				if (!$validated) {
					$this->throttle([ 'reconfirmPassword', $this->getIpAddress() ], 3, (60 * 60), 4, false);
				}

				return $validated;
			}
			else {
				throw new NotLoggedInException();
			}
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Logs the user out
	 *
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function logOut() {
		// if the user has been signed in
		if ($this->isLoggedIn()) {
			// retrieve any locally existing remember directive
			$rememberDirectiveSelector = $this->getRememberDirectiveSelector();

			// remove all session variables maintained by this library
			unset($_SESSION['user_session_id']);
		}
	}

	/**
	 * Creates a new directive keeping the user logged in ("remember me")
	 *
	 * @param int $userId the user ID to keep signed in
	 * @param int $duration the duration in seconds
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function createRememberDirective($userId, $duration) {
		$selector = self::createRandomString(24);
		$token = self::createRandomString(32);
		$tokenHashed = \password_hash($token, \PASSWORD_DEFAULT);
		$expires = \time() + ((int) $duration);

		try {
			$this->db->insert(
				$this->makeTableNameComponents('users_remembered'),
				[
					'user' => $userId,
					'selector' => $selector,
					'token' => $tokenHashed,
					'expires' => $expires
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		$this->setRememberCookie($selector, $token, $expires);
	}

	protected function deleteRememberDirectiveForUserById($userId, $selector = null) {
		parent::deleteRememberDirectiveForUserById($userId, $selector);

		$this->setRememberCookie(null, null, \time() - 3600);
	}

	/**
	 * Sets or updates the cookie that manages the "remember me" token
	 *
	 * @param string|null $selector the selector from the selector/token pair
	 * @param string|null $token the token from the selector/token pair
	 * @param int $expires the UNIX time in seconds which the token should expire at
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function setRememberCookie($selector, $token, $expires) {
		$params = \session_get_cookie_params();

		if (isset($selector) && isset($token)) {
			$content = $selector . self::COOKIE_CONTENT_SEPARATOR . $token;
		}
		else {
			$content = '';
		}

		// save the cookie with the selector and token (requests a cookie to be written on the client)
		$cookie = new Cookie($this->rememberCookieName);
		$cookie->setValue($content);
		$cookie->setExpiryTime($expires);
		$cookie->setPath($params['path']);
		$cookie->setDomain($params['domain']);
		$cookie->setHttpOnly($params['httponly']);
		$cookie->setSecureOnly($params['secure']);
		$result = $cookie->save();

		if ($result === false) {
			throw new HeadersAlreadySentError();
		}

		// if we've been deleting the cookie above
		if (!isset($selector) || !isset($token)) {
			// attempt to delete a potential old cookie from versions v1.x.x to v6.x.x as well (requests a cookie to be written on the client)
			$cookie = new Cookie('auth_remember');
			$cookie->setPath((!empty($params['path'])) ? $params['path'] : '/');
			$cookie->setDomain($params['domain']);
			$cookie->setHttpOnly($params['httponly']);
			$cookie->setSecureOnly($params['secure']);
			$cookie->delete();
		}
	}

	protected function onLoginSuccessful($userId, $email, $username, $status, $roles, $forceLogout, $remembered) {
		// update the timestamp of the user's last login
		try {
			$this->db->update(
				$this->makeTableNameComponents('users'),
				[ 'last_login' => \time() ],
				[ 'id' => $userId ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		parent::onLoginSuccessful($userId, $email, $username, $status, $roles, $forceLogout, $remembered);
	}

	/**
	 * Deletes the session cookie on the client
	 *
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function deleteSessionCookie() {
		$params = \session_get_cookie_params();

		// ask for the session cookie to be deleted (requests a cookie to be written on the client)
		$cookie = new Cookie(\session_name());
		$cookie->setPath($params['path']);
		$cookie->setDomain($params['domain']);
		$cookie->setHttpOnly($params['httponly']);
		$cookie->setSecureOnly($params['secure']);
		$result = $cookie->delete();

		if ($result === false) {
			throw new HeadersAlreadySentError();
		}
	}

	/**
	 * Confirms an email address (and activates the account) by supplying the correct selector/token pair
	 *
	 * The selector/token pair must have been generated previously by registering a new account
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @return string[] an array with the old email address (if any) at index zero and the new email address (which has just been verified) at index one
	 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
	 * @throws TokenExpiredException if the token has already expired
	 * @throws UserAlreadyExistsException if an attempt has been made to change the email address to a (now) occupied address
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function confirmEmail($selector, $token) {
		$this->throttle([ 'confirmEmail', $this->getIpAddress() ], 5, (60 * 60), 10);
		$this->throttle([ 'confirmEmail', 'selector', $selector ], 3, (60 * 60), 10);
		$this->throttle([ 'confirmEmail', 'token', $token ], 3, (60 * 60), 10);

		try {
			$confirmationData = $this->db->selectRow(
				'SELECT a.id, a.user_id, a.email AS new_email, a.token, a.expires, b.email AS old_email FROM ' . $this->makeTableName('users_confirmations') . ' AS a JOIN ' . $this->makeTableName('users') . ' AS b ON b.id = a.user_id WHERE a.selector = ?',
				[ $selector ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if (!empty($confirmationData)) {
			if (\password_verify($token, $confirmationData['token'])) {
				if ($confirmationData['expires'] >= \time()) {
					// invalidate any potential outstanding password reset requests
					try {
						$this->db->delete(
							$this->makeTableNameComponents('users_resets'),
							[ 'user' => $confirmationData['user_id'] ]
						);
					}
					catch (Error $e) {
						throw new DatabaseError($e->getMessage());
					}

					// mark the email address as verified (and possibly update it to the new address given)
					try {
						$this->db->update(
							$this->makeTableNameComponents('users'),
							[
								'email' => $confirmationData['new_email'],
								'verified' => 1
							],
							[ 'id' => $confirmationData['user_id'] ]
						);
					}
					catch (IntegrityConstraintViolationException $e) {
						throw new UserAlreadyExistsException();
					}
					catch (Error $e) {
						throw new DatabaseError($e->getMessage());
					}

					// if the user is currently signed in
					if ($this->isLoggedIn()) {
						// if the user has just confirmed an email address for their own account
						if ($this->getUserId() === $confirmationData['user_id']) {
							// immediately update the email address in the current session as well
							$_SESSION[self::SESSION_FIELD_EMAIL] = $confirmationData['new_email'];
						}
					}

					// consume the token just being used for confirmation
					try {
						$this->db->delete(
							$this->makeTableNameComponents('users_confirmations'),
							[ 'id' => $confirmationData['id'] ]
						);
					}
					catch (Error $e) {
						throw new DatabaseError($e->getMessage());
					}

					// if the email address has not been changed but simply been verified
					if ($confirmationData['old_email'] === $confirmationData['new_email']) {
						// the output should not contain any previous email address
						$confirmationData['old_email'] = null;
					}

					return [
						$confirmationData['old_email'],
						$confirmationData['new_email']
					];
				}
				else {
					throw new TokenExpiredException();
				}
			}
			else {
				throw new InvalidSelectorTokenPairException();
			}
		}
		else {
			throw new InvalidSelectorTokenPairException();
		}
	}

	/**
	 * Confirms an email address and activates the account by supplying the correct selector/token pair
	 *
	 * The selector/token pair must have been generated previously by registering a new account
	 *
	 * The user will be automatically signed in if this operation is successful
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @param int|null $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
	 * @return string[] an array with the old email address (if any) at index zero and the new email address (which has just been verified) at index one
	 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
	 * @throws TokenExpiredException if the token has already expired
	 * @throws UserAlreadyExistsException if an attempt has been made to change the email address to a (now) occupied address
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function confirmEmailAndSignIn($selector, $token, $rememberDuration = null) {
		$emailBeforeAndAfter = $this->confirmEmail($selector, $token);

		if (!$this->isLoggedIn()) {
			if ($emailBeforeAndAfter[1] !== null) {
				$emailBeforeAndAfter[1] = self::validateEmailAddress($emailBeforeAndAfter[1]);

				$userData = $this->getUserDataByEmailAddress(
					$emailBeforeAndAfter[1],
					[ 'id', 'email', 'username', 'status', 'roles_mask', 'force_logout' ]
				);

				$this->onLoginSuccessful($userData['id'], $userData['email'], $userData['username'], $userData['status'], $userData['roles_mask'], $userData['force_logout'], true);

				if ($rememberDuration !== null) {
					$this->createRememberDirective($userData['id'], $rememberDuration);
				}
			}
		}

		return $emailBeforeAndAfter;
	}

	/**
	 * Changes the currently signed-in user's password while requiring the old password for verification
	 *
	 * @param string $oldPassword the old password to verify account ownership
	 * @param string $newPassword the new password that should be set
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws InvalidPasswordException if either the old password has been wrong or the desired new one has been invalid
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function changePassword($oldPassword, $newPassword) {
		if ($this->reconfirmPassword($oldPassword)) {
			$this->changePasswordWithoutOldPassword($newPassword);
		}
		else {
			throw new InvalidPasswordException();
		}
	}

	/**
	 * Changes the currently signed-in user's password without requiring the old password for verification
	 *
	 * @param string $newPassword the new password that should be set
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws InvalidPasswordException if the desired new password has been invalid
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function changePasswordWithoutOldPassword($newPassword) {
		if ($this->isLoggedIn()) {
			$newPassword = self::validatePassword($newPassword);
			$this->updatePasswordInternal($this->getUserId(), $newPassword);

			try {
				$this->logOutEverywhereElse();
			}
			catch (NotLoggedInException $ignored) {}
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Attempts to change the email address of the currently signed-in user (which requires confirmation)
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to verify their email address as a next step, both pieces will be required again
	 *
	 * @param string $newEmail the desired new email address
	 * @param callable $callback the function that sends the confirmation email to the user
	 * @throws InvalidEmailException if the desired new email address is invalid
	 * @throws UserAlreadyExistsException if a user with the desired new email address already exists
	 * @throws EmailNotVerifiedException if the current (old) email address has not been verified yet
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see confirmEmail
	 * @see confirmEmailAndSignIn
	 */
	public function changeEmail($newEmail, callable $callback) {
		if ($this->isLoggedIn()) {
			$newEmail = self::validateEmailAddress($newEmail);

			$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);

			try {
				$existingUsersWithNewEmail = $this->db->selectValue(
					'SELECT COUNT(*) FROM ' . $this->makeTableName('users') . ' WHERE email = ?',
					[ $newEmail ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			if ((int) $existingUsersWithNewEmail !== 0) {
				throw new UserAlreadyExistsException();
			}

			try {
				$verified = $this->db->selectValue(
					'SELECT verified FROM ' . $this->makeTableName('users') . ' WHERE id = ?',
					[ $this->getUserId() ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			// ensure that at least the current (old) email address has been verified before proceeding
			if ((int) $verified !== 1) {
				throw new EmailNotVerifiedException();
			}

			$this->throttle([ 'requestEmailChange', 'userId', $this->getUserId() ], 1, (60 * 60 * 24));
			$this->throttle([ 'requestEmailChange', $this->getIpAddress() ], 1, (60 * 60 * 24), 3);

			$this->createConfirmationRequest($this->getUserId(), $newEmail, $callback);
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Attempts to re-send an earlier confirmation request for the user with the specified email address
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to verify their email address as a next step, both pieces will be required again
	 *
	 * @param string $email the email address of the user to re-send the confirmation request for
	 * @param callable $callback the function that sends the confirmation request to the user
	 * @throws ConfirmationRequestNotFound if no previous request has been found that could be re-sent
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 */
	public function resendConfirmationForEmail($email, callable $callback) {
		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);

		$this->resendConfirmationForColumnValue('email', $email, $callback);
	}

	/**
	 * Attempts to re-send an earlier confirmation request for the user with the specified ID
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to verify their email address as a next step, both pieces will be required again
	 *
	 * @param int $userId the ID of the user to re-send the confirmation request for
	 * @param callable $callback the function that sends the confirmation request to the user
	 * @throws ConfirmationRequestNotFound if no previous request has been found that could be re-sent
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 */
	public function resendConfirmationForUserId($userId, callable $callback) {
		$this->resendConfirmationForColumnValue('user_id', $userId, $callback);
	}

	/**
	 * Attempts to re-send an earlier confirmation request
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to verify their email address as a next step, both pieces will be required again
	 *
	 * You must never pass untrusted input to the parameter that takes the column name
	 *
	 * @param string $columnName the name of the column to filter by
	 * @param mixed $columnValue the value to look for in the selected column
	 * @param callable $callback the function that sends the confirmation request to the user
	 * @throws ConfirmationRequestNotFound if no previous request has been found that could be re-sent
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function resendConfirmationForColumnValue($columnName, $columnValue, callable $callback) {
		try {
			$latestAttempt = $this->db->selectRow(
				'SELECT user_id, email FROM ' . $this->makeTableName('users_confirmations') . ' WHERE ' . $columnName . ' = ? ORDER BY id DESC LIMIT 1 OFFSET 0',
				[ $columnValue ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if ($latestAttempt === null) {
			throw new ConfirmationRequestNotFound();
		}

		$this->throttle([ 'resendConfirmation', 'userId', $latestAttempt['user_id'] ], 1, (60 * 60 * 6));
		$this->throttle([ 'resendConfirmation', $this->getIpAddress() ], 4, (60 * 60 * 24 * 7), 2);

		$this->createConfirmationRequest(
			$latestAttempt['user_id'],
			$latestAttempt['email'],
			$callback
		);
	}

	/**
	 * Initiates a password reset request for the user with the specified email address
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to proceed to the second step of the password reset, both pieces will be required again
	 *
	 * @param string $email the email address of the user who wants to request the password reset
	 * @param callable $callback the function that sends the password reset information to the user
	 * @param int|null $requestExpiresAfter (optional) the interval in seconds after which the request should expire
	 * @param int|null $maxOpenRequests (optional) the maximum number of unexpired and unused requests per user
	 * @throws InvalidEmailException if the email address was invalid or could not be found
	 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
	 * @throws ResetDisabledException if the user has explicitly disabled password resets for their account
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see canResetPasswordOrThrow
	 * @see canResetPassword
	 * @see resetPassword
	 * @see resetPasswordAndSignIn
	 */
	public function forgotPassword($email, callable $callback, $requestExpiresAfter = null, $maxOpenRequests = null) {
		$email = self::validateEmailAddress($email);

		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);

		if ($requestExpiresAfter === null) {
			// use six hours as the default
			$requestExpiresAfter = 60 * 60 * 6;
		}
		else {
			$requestExpiresAfter = (int) $requestExpiresAfter;
		}

		if ($maxOpenRequests === null) {
			// use two requests per user as the default
			$maxOpenRequests = 2;
		}
		else {
			$maxOpenRequests = (int) $maxOpenRequests;
		}

		$userData = $this->getUserDataByEmailAddress(
			$email,
			[ 'id', 'verified', 'resettable' ]
		);

		// ensure that the account has been verified before initiating a password reset
		if ((int) $userData['verified'] !== 1) {
			throw new EmailNotVerifiedException();
		}

		// do not allow a password reset if the user has explicitly disabled this feature
		if ((int) $userData['resettable'] !== 1) {
			throw new ResetDisabledException();
		}

		$openRequests = $this->throttling ? (int) $this->getOpenPasswordResetRequests($userData['id']) : 0;

		if ($openRequests < $maxOpenRequests) {
			$this->throttle([ 'requestPasswordReset', $this->getIpAddress() ], 4, (60 * 60 * 24 * 7), 2);
			$this->throttle([ 'requestPasswordReset', 'user', $userData['id'] ], 4, (60 * 60 * 24 * 7), 2);

			$this->createPasswordResetRequest($userData['id'], $requestExpiresAfter, $callback);
		}
		else {
			throw new TooManyRequestsException('', $requestExpiresAfter);
		}
	}

	/**
	 * Authenticates an existing user
	 *
	 * @param string $password the user's password
	 * @param string|null $email (optional) the user's email address
	 * @param string|null $username (optional) the user's username
	 * @param int|null $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
	 * @param callable|null $onBeforeSuccess (optional) a function that receives the user's ID as its single parameter and is executed before successful authentication; must return `true` to proceed or `false` to cancel
	 * @throws InvalidEmailException if the email address was invalid or could not be found
	 * @throws UnknownUsernameException if an attempt has been made to authenticate with a non-existing username
	 * @throws AmbiguousUsernameException if an attempt has been made to authenticate with an ambiguous username
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
	 * @throws AttemptCancelledException if the attempt has been cancelled by the supplied callback that is executed before success
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function authenticateUserInternal($password, $email = null, $username = null, $rememberDuration = null, callable $onBeforeSuccess = null) {
		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);
		$this->throttle([ 'attemptToLogin', $this->getIpAddress() ], 4, (60 * 60), 5, true);

		$columnsToFetch = [ 'id', 'email', 'password', 'verified', 'username', 'status', 'roles_mask', 'force_logout' ];

		if ($email !== null) {
			$email = self::validateEmailAddress($email);

			// attempt to look up the account information using the specified email address
			$userData = $this->getUserDataByEmailAddress(
				$email,
				$columnsToFetch
			);
		}
		elseif ($username !== null) {
			$username = \trim($username);

			// attempt to look up the account information using the specified username
			$userData = $this->getUserDataByUsername(
				$username,
				$columnsToFetch
			);
		}
		// if neither an email address nor a username has been provided
		else {
			// we can't do anything here because the method call has been invalid
			throw new EmailOrUsernameRequiredError();
		}

		$password = self::validatePassword($password);

		if (\password_verify($password, $userData['password'])) {
			// if the password needs to be re-hashed to keep up with improving password cracking techniques
			if (\password_needs_rehash($userData['password'], \PASSWORD_DEFAULT)) {
				// create a new hash from the password and update it in the database
				$this->updatePasswordInternal($userData['id'], $password);
			}

			if ((int) $userData['verified'] === 1) {
				if (!isset($onBeforeSuccess) || (\is_callable($onBeforeSuccess) && $onBeforeSuccess($userData['id']) === true)) {
					$this->onLoginSuccessful($userData['id'], $userData['email'], $userData['username'], $userData['status'], $userData['roles_mask'], $userData['force_logout'], false);

					// continue to support the old parameter format
					if ($rememberDuration === true) {
						$rememberDuration = 60 * 60 * 24 * 28;
					}
					elseif ($rememberDuration === false) {
						$rememberDuration = null;
					}

					if ($rememberDuration !== null) {
						$this->createRememberDirective($userData['id'], $rememberDuration);
					}

					return;
				}
				else {
					$this->throttle([ 'attemptToLogin', $this->getIpAddress() ], 4, (60 * 60), 5, false);

					if (isset($email)) {
						$this->throttle([ 'attemptToLogin', 'email', $email ], 500, (60 * 60 * 24), null, false);
					}
					elseif (isset($username)) {
						$this->throttle([ 'attemptToLogin', 'username', $username ], 500, (60 * 60 * 24), null, false);
					}

					throw new AttemptCancelledException();
				}
			}
			else {
				throw new EmailNotVerifiedException();
			}
		}
		else {
			$this->throttle([ 'attemptToLogin', $this->getIpAddress() ], 4, (60 * 60), 5, false);

			if (isset($email)) {
				$this->throttle([ 'attemptToLogin', 'email', $email ], 500, (60 * 60 * 24), null, false);
			}
			elseif (isset($username)) {
				$this->throttle([ 'attemptToLogin', 'username', $username ], 500, (60 * 60 * 24), null, false);
			}

			// we cannot authenticate the user due to the password being wrong
			throw new InvalidPasswordException();
		}
	}

	/**
	 * Returns the requested user data for the account with the specified email address (if any)
	 *
	 * You must never pass untrusted input to the parameter that takes the column list
	 *
	 * @param string $email the email address to look for
	 * @param array $requestedColumns the columns to request from the user's record
	 * @return array the user data (if an account was found)
	 * @throws InvalidEmailException if the email address could not be found
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function getUserDataByEmailAddress($email, array $requestedColumns) {
		try {
			$projection = \implode(', ', $requestedColumns);
			$userData = $this->db->selectRow(
				'SELECT ' . $projection . ' FROM ' . $this->makeTableName('users') . ' WHERE email = ?',
				[ $email ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if (!empty($userData)) {
			return $userData;
		}
		else {
			throw new InvalidEmailException();
		}
	}

	/**
	 * Returns the number of open requests for a password reset by the specified user
	 *
	 * @param int $userId the ID of the user to check the requests for
	 * @return int the number of open requests for a password reset
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function getOpenPasswordResetRequests($userId) {
		try {
			$requests = $this->db->selectValue(
				'SELECT COUNT(*) FROM ' . $this->makeTableName('users_resets') . ' WHERE user = ? AND expires > ?',
				[
					$userId,
					\time()
				]
			);

			if (!empty($requests)) {
				return $requests;
			}
			else {
				return 0;
			}
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}
	}

	/**
	 * Creates a new password reset request
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to proceed to the second step of the password reset, both pieces will be required again
	 *
	 * @param int $userId the ID of the user who requested the reset
	 * @param int $expiresAfter the interval in seconds after which the request should expire
	 * @param callable $callback the function that sends the password reset information to the user
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function createPasswordResetRequest($userId, $expiresAfter, callable $callback) {
		$selector = self::createRandomString(20);
		$token = self::createRandomString(20);
		$tokenHashed = \password_hash($token, \PASSWORD_DEFAULT);
		$expiresAt = \time() + $expiresAfter;

		try {
			$this->db->insert(
				$this->makeTableNameComponents('users_resets'),
				[
					'user' => $userId,
					'selector' => $selector,
					'token' => $tokenHashed,
					'expires' => $expiresAt
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if (\is_callable($callback)) {
			$callback($selector, $token);
		}
		else {
			throw new MissingCallbackError();
		}
	}

	/**
	 * Resets the password for a particular account by supplying the correct selector/token pair
	 *
	 * The selector/token pair must have been generated previously by calling {@see forgotPassword}
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @param string $newPassword the new password to set for the account
	 * @return string[] an array with the user's ID at index `id` and the user's email address at index `email`
	 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
	 * @throws TokenExpiredException if the token has already expired
	 * @throws ResetDisabledException if the user has explicitly disabled password resets for their account
	 * @throws InvalidPasswordException if the new password was invalid
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see forgotPassword
	 * @see canResetPasswordOrThrow
	 * @see canResetPassword
	 * @see resetPasswordAndSignIn
	 */
	public function resetPassword($selector, $token, $newPassword) {
		$this->throttle([ 'resetPassword', $this->getIpAddress() ], 5, (60 * 60), 10);
		$this->throttle([ 'resetPassword', 'selector', $selector ], 3, (60 * 60), 10);
		$this->throttle([ 'resetPassword', 'token', $token ], 3, (60 * 60), 10);

		try {
			$resetData = $this->db->selectRow(
				'SELECT a.id, a.user, a.token, a.expires, b.email, b.resettable FROM ' . $this->makeTableName('users_resets') . ' AS a JOIN ' . $this->makeTableName('users') . ' AS b ON b.id = a.user WHERE a.selector = ?',
				[ $selector ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if (!empty($resetData)) {
			if ((int) $resetData['resettable'] === 1) {
				if (\password_verify($token, $resetData['token'])) {
					if ($resetData['expires'] >= \time()) {
						$newPassword = self::validatePassword($newPassword);
						$this->updatePasswordInternal($resetData['user'], $newPassword);
						$this->forceLogoutForUserById($resetData['user']);

						try {
							$this->db->delete(
								$this->makeTableNameComponents('users_resets'),
								[ 'id' => $resetData['id'] ]
							);
						}
						catch (Error $e) {
							throw new DatabaseError($e->getMessage());
						}

						return [
							'id' => $resetData['user'],
							'email' => $resetData['email']
						];
					}
					else {
						throw new TokenExpiredException();
					}
				}
				else {
					throw new InvalidSelectorTokenPairException();
				}
			}
			else {
				throw new ResetDisabledException();
			}
		}
		else {
			throw new InvalidSelectorTokenPairException();
		}
	}

	/**
	 * Resets the password for a particular account by supplying the correct selector/token pair
	 *
	 * The selector/token pair must have been generated previously by calling {@see forgotPassword}
	 *
	 * The user will be automatically signed in if this operation is successful
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @param string $newPassword the new password to set for the account
	 * @param int|null $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
	 * @return string[] an array with the user's ID at index `id` and the user's email address at index `email`
	 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
	 * @throws TokenExpiredException if the token has already expired
	 * @throws ResetDisabledException if the user has explicitly disabled password resets for their account
	 * @throws InvalidPasswordException if the new password was invalid
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see forgotPassword
	 * @see canResetPasswordOrThrow
	 * @see canResetPassword
	 * @see resetPassword
	 */
	public function resetPasswordAndSignIn($selector, $token, $newPassword, $rememberDuration = null) {
		$idAndEmail = $this->resetPassword($selector, $token, $newPassword);

		if (!$this->isLoggedIn()) {
			$idAndEmail['email'] = self::validateEmailAddress($idAndEmail['email']);

			$userData = $this->getUserDataByEmailAddress(
				$idAndEmail['email'],
				[ 'username', 'status', 'roles_mask', 'force_logout' ]
			);

			$this->onLoginSuccessful($idAndEmail['id'], $idAndEmail['email'], $userData['username'], $userData['status'], $userData['roles_mask'], $userData['force_logout'], true);

			if ($rememberDuration !== null) {
				$this->createRememberDirective($idAndEmail['id'], $rememberDuration);
			}
		}

		return $idAndEmail;
	}

	/**
	 * Check if the supplied selector/token pair can be used to reset a password
	 *
	 * The password can be reset using the supplied information if this method does *not* throw any exception
	 *
	 * The selector/token pair must have been generated previously by calling {@see forgotPassword}
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
	 * @throws TokenExpiredException if the token has already expired
	 * @throws ResetDisabledException if the user has explicitly disabled password resets for their account
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see forgotPassword
	 * @see canResetPassword
	 * @see resetPassword
	 * @see resetPasswordAndSignIn
	 */
	public function canResetPasswordOrThrow($selector, $token) {
		try {
			// pass an invalid password intentionally to force an expected error
			$this->resetPassword($selector, $token, null);

			// we should already be in one of the `catch` blocks now so this is not expected
			throw new AuthError();
		}
		// if the password is the only thing that's invalid
		catch (InvalidPasswordException $ignored) {
			// the password can be reset
		}
		// if some other things failed (as well)
		catch (AuthException $e) {
			// re-throw the exception
			throw $e;
		}
	}

	/**
	 * Check if the supplied selector/token pair can be used to reset a password
	 *
	 * The selector/token pair must have been generated previously by calling {@see forgotPassword}
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @return bool whether the password can be reset using the supplied information
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see forgotPassword
	 * @see canResetPasswordOrThrow
	 * @see resetPassword
	 * @see resetPasswordAndSignIn
	 */
	public function canResetPassword($selector, $token) {
		try {
			$this->canResetPasswordOrThrow($selector, $token);

			return true;
		}
		catch (AuthException $e) {
			return false;
		}
	}

	/**
	 * Sets whether password resets should be permitted for the account of the currently signed-in user
	 *
	 * @param bool $enabled whether password resets should be enabled for the user's account
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function setPasswordResetEnabled($enabled) {
		$enabled = (bool) $enabled;

		if ($this->isLoggedIn()) {
			try {
				$this->db->update(
					$this->makeTableNameComponents('users'),
					[
						'resettable' => $enabled ? 1 : 0
					],
					[
						'id' => $this->getUserId()
					]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}
		}
		else {
			throw new NotLoggedInException();
		}
	}

	public function check() {
		return isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_LOGGED_IN]) && $_SESSION[self::SESSION_FIELD_LOGGED_IN] === true;
	}

	/**
	 * Returns the currently signed-in user's ID by reading from the session
	 *
	 * @return int the user ID
	 */
	public function getUser() {
		if (isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_USER_ID])) {
			return $_SESSION[self::SESSION_FIELD_USER_ID];
		}
		else {
			return null;
		}
	}

	/**
	 * Returns the user's current IP address
	 *
	 * @return string the IP address (IPv4 or IPv6)
	 */
	public function getIpAddress() {
		return $this->ipAddress;
	}

	public function admin() {
		return new Administration($this->db, $this->dbTablePrefix, $this->dbSchema);
	}
}
