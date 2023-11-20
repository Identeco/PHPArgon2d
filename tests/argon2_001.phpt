--TEST--
Tests Argon2d constants are defined
--FILE--
<?php
var_dump(VERSION_10);
var_dump(VERSION_13);
--EXPECT--
int(16)
int(19)
