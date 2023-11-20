--TEST--
Tests argon2d_raw_hash credential check
--FILE--
<?php
var_dump(bin2hex(argon2d_raw_hash("test@example.com","StaticSalt",512,1,1,32,VERSION_13)));
--EXPECTF--
Notice: argon2d_raw_hash(): For password hashing, the salt should be randomly chosen for each password with at least 16 bytes in %s on line %d

Notice: argon2d_raw_hash(): To compute secure password hashes with one iteration, the memory should at least exceed 47104 KiB in %s on line %d
string(64) "e2a8f54c300962421342d44ed2ad2924fd34024720136367e10ae58bc86676b8"
