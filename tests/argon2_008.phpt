--TEST--
Tests argon2d_password_hash exceptions
--FILE--
<?php
try {
    argon2d_password_hash("password",-1,1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash("password",65536,-1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash("password",65536,1,-1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash("password",65536,1,1,-1);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash("password",512,1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash("password",512,2,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash("password",512,3,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash("password",512,4,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash("password",512,5,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash("password",512,6,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash("password",512,7,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
--EXPECT--
string(64) "Memory must be in the value range from (8*parallelism) to 2^32-1"
string(54) "Iterations must be in the value range from 1 to 2^32-1"
string(52) "Parallelism must be in the value range from 1 to 255"
string(40) "Version must be VERSION_13 or VERSION_10"
string(95) "To compute secure password hashes with one iteration, the memory must at least exceed 47104 KiB"
string(95) "To compute secure password hashes with two iteration, the memory must at least exceed 19456 KiB"
string(97) "To compute secure password hashes with three iteration, the memory must at least exceed 12288 KiB"
string(95) "To compute secure password hashes with four iteration, the memory must at least exceed 9216 KiB"
string(95) "To compute secure password hashes with five iteration, the memory must at least exceed 7168 KiB"
string(105) "To compute secure password hashes with more then five iteration, the memory must at least exceed 7168 KiB"
string(105) "To compute secure password hashes with more then five iteration, the memory must at least exceed 7168 KiB"
