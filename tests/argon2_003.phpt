--TEST--
Tests argon2d_raw_hash version 1.0 and 1.3
--FILE--
<?php
var_dump(bin2hex(argon2d_raw_hash("password","RandomSaltForEachPassword",65536,3,4,32,VERSION_13)));
var_dump(bin2hex(argon2d_raw_hash("password","RandomSaltForEachPassword",65536,3,4,32,VERSION_10)));
--EXPECT--
string(64) "dd4714e54bfd2ce5cbd5559db0768a31a2f70dc09c01166e0f614f5ec0d30537"
string(64) "8ea8c7ec38cad4e60d192d8a7f48a4ba4ea4c555747435d4c882ebe0bdbb4c09"
