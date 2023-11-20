--TEST--
Tests argon2d_raw_hash warning messages
--FILE--
<?php
var_dump(bin2hex(argon2d_raw_hash("password","RandomSalt",512,1,1,8,VERSION_13,"secret","ad")));
--EXPECTF--
Notice: argon2d_raw_hash(): For password hashing, the salt should be randomly chosen for each password with at least 16 bytes in %s on line %d

Notice: argon2d_raw_hash(): For password hashing the tag length should be at least 32 bytes in %s on line %d

Notice: argon2d_raw_hash(): For password hashing the secret key should be at least 14 bytes in %s on line %d

Notice: argon2d_raw_hash(): To compute secure password hashes with one iteration, the memory should at least exceed 47104 KiB in %s on line %d
string(16) "123e9b6acd0ea41e"
