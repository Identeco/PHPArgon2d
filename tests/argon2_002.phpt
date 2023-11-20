--TEST--
Tests argon2d_raw_hash rfc test vector
--FILE--
<?php
var_dump(bin2hex(argon2d_raw_hash(hex2bin("0101010101010101010101010101010101010101010101010101010101010101"), hex2bin("02020202020202020202020202020202"),32,3,4,32,VERSION_13,hex2bin("0303030303030303"), hex2bin("040404040404040404040404"))));
--EXPECTF--
Notice: argon2d_raw_hash(): For password hashing the secret key should be at least 14 bytes in %s on line %d

Notice: argon2d_raw_hash(): To compute secure password hashes with three iteration, the memory should at least exceed 12288 KiB in %s on line %d
string(64) "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"
