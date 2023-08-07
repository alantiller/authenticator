# Authenticator

The simple, secure and easy to use authentication library. I felt like there wasn't a simple and easy to use library in existance for fully customisable authentication so I decided to write this library.

## Installation

There are two steps to installing this library, there is the installation of the physical library and then the installation of the database.

### Installation via composer

Installation is easy

```
composer install alantiller/authenticator
```

### Database installation



## Creating an instance

```php
$auth = new AlanTiller/Authenticator($pdo);
```


## Session Authentication

### Login

```php
$auth->session()->login($email, $password)
```

### Check

### Logout


## User Management

### Get a user

```php
$result = $auth->user()->get($id);
```

### Get me

```php
$result = $auth->user()->me();
```



```php
$result = $auth->user()->create([
    "firstname" => "John",
    "surname" => "Smith",
    "email" => "johnsmith@example.com",
    "password" => "Pa33w0rd@1",
    "confirm_email" => 0, #set this to 1 if you want the email to confirm without having to send an email
]);
```



There are two diffrent types of authentication in this library session and token. Session auththentication 


self::createRandomString(16) -> TokenGenerator::generateToken(16)

createUserInternal -> createUser





// Gets the current user


// login


// login
$auth->token()->login($email, $password)

// logout
$auth->auth($token)

// Checks the current auth
$auth->auth()->check();

// Checks the auth of a token
$auth->auth()->check($token);

// Checks the current permission
$auth->permission->