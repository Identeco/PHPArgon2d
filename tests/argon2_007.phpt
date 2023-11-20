--TEST--
Tests argon2d_raw_hash exceptions
--FILE--
<?php
try {
    argon2d_raw_hash("password", "SHORT",65536,1,1,32,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_raw_hash("password", "RandomSaltForEachPassword",-1,1,1,32,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_raw_hash("password", "RandomSaltForEachPassword",65536,-1,1,32,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_raw_hash("password", "RandomSaltForEachPassword",65536,1,-1,32,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_raw_hash("password", "RandomSaltForEachPassword",65536,1,1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_raw_hash("password", "RandomSaltForEachPassword",65536,1,1,32,-1);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}

--EXPECT--
string(54) "Salt must be in the value range from 8 to 2^32-1 bytes"
string(64) "Memory must be in the value range from (8*parallelism) to 2^32-1"
string(54) "Iterations must be in the value range from 1 to 2^32-1"
string(55) "Parallelism must be in the value range from 1 to 2^24-1"
string(60) "Tag length must be in the value range from 4 to 2^32-1 bytes"
string(40) "Version must be VERSION_13 or VERSION_10"
