--TEST--
Tests argon2d_passwort_hash, argon2d_passwort_hash_verify, argon2d_passwort_hash_need_rehash without optional parameters
--FILE--
<?php
$hash=argon2d_password_hash("password");
var_dump(argon2d_password_hash_verify($hash, "password"));
var_dump(argon2d_password_hash_verify($hash, "wrong_password"));
var_dump(argon2d_password_hash_need_rehash($hash));
--EXPECT--
bool(true)
bool(false)
bool(false)
