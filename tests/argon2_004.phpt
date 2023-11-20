--TEST--
Tests argon2d_raw_hash without optinal data
--FILE--
<?php
var_dump(bin2hex(argon2d_raw_hash("password","RandomSaltForEachStoredPassword")));
var_dump(bin2hex(argon2d_raw_hash("password","RandomSaltForEachStoredPassword",DEFAULT_VALUE,DEFAULT_VALUE,DEFAULT_VALUE,DEFAULT_VALUE,DEFAULT_VALUE)));
--EXPECTF--
string(64) "ad3b77a720fd991bddfb19e8cb1339d5b1845d0e9261444560c94cd2abaeed0f"
string(64) "ad3b77a720fd991bddfb19e8cb1339d5b1845d0e9261444560c94cd2abaeed0f"
