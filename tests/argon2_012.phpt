--TEST--
Tests argon2d_password_hash_need_rehash with parameters
--FILE--
<?php
var_dump(argon2d_password_hash_need_rehash('$argon2d$v=19$m=32768,t=3,p=4$NThzRmFWUlZNNjhYM3FLeQ$qrvsv71DIzPwIy/ZWUM7B6M1As6/bAMQiDiwT9OZ7xg',32768,3,4,VERSION_13));
var_dump(argon2d_password_hash_need_rehash('$argon2d$v=16$m=32768,t=3,p=4$NThzRmFWUlZNNjhYM3FLeQ$qrvsv71DIzPwIy/ZWUM7B6M1As6/bAMQiDiwT9OZ7xg',32768,3,4,VERSION_13));
var_dump(argon2d_password_hash_need_rehash('$argon2d$v=19$m=32768,t=2,p=4$NThzRmFWUlZNNjhYM3FLeQ$qrvsv71DIzPwIy/ZWUM7B6M1As6/bAMQiDiwT9OZ7xg',32768,3,4,VERSION_13));
var_dump(argon2d_password_hash_need_rehash('$argon2d$v=19$m=32768,t=3,p=3$NThzRmFWUlZNNjhYM3FLeQ$qrvsv71DIzPwIy/ZWUM7B6M1As6/bAMQiDiwT9OZ7xg',32768,3,4,VERSION_13));
--EXPECT--
bool(false)
bool(true)
bool(true)
bool(true)

