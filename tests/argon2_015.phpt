--TEST--
Tests argon2d_passwort_hash, argon2d_passwort_hash_verify, argon2d_passwort_hash_need_rehash with parameters
--FILE--
<?php
$hash_v10=argon2d_password_hash("password1",65536,1,1,VERSION_10);
$hash_v13=argon2d_password_hash("password2",65536,1,1,VERSION_13);
var_dump(argon2d_password_hash_verify($hash_v10, "password1"));
var_dump(argon2d_password_hash_verify($hash_v10, "wrong_password"));
var_dump(argon2d_password_hash_need_rehash($hash_v10,65536,1,1,VERSION_10));
var_dump(argon2d_password_hash_need_rehash($hash_v10));
var_dump(argon2d_password_hash_verify($hash_v13, "password2"));
var_dump(argon2d_password_hash_verify($hash_v13, "wrong_password"));
var_dump(argon2d_password_hash_need_rehash($hash_v13,65536,1,1,VERSION_13));
var_dump(argon2d_password_hash_need_rehash($hash_v13));
var_dump(argon2d_password_hash_verify($hash_v10, "password2"));
var_dump(argon2d_password_hash_verify($hash_v13, "password1"));
--EXPECT--
bool(true)
bool(false)
bool(false)
bool(true)
bool(true)
bool(false)
bool(false)
bool(true)
bool(false)
bool(false)

