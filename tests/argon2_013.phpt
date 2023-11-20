--TEST--
Tests argon2d_password_hash_need_rehash with insecure parameters
--FILE--
<?php
var_dump(argon2d_password_hash_need_rehash('$argon2d$v=19$m=512,t=1,p=4$NThzRmFWUlZNNjhYM3FLeQ$qrvsv71DIzPwIy/ZWUM7B6M1As6/bAMQiDiwT9OZ7xg',512,1,4,VERSION_13));
var_dump(argon2d_password_hash_need_rehash('$argon2d$v=19$m=512,t=2,p=4$NThzRmFWUlZNNjhYM3FLeQ$qrvsv71DIzPwIy/ZWUM7B6M1As6/bAMQiDiwT9OZ7xg',512,1,4,VERSION_13));
var_dump(argon2d_password_hash_need_rehash('$argon2d$v=19$m=512,t=3,p=4$NThzRmFWUlZNNjhYM3FLeQ$qrvsv71DIzPwIy/ZWUM7B6M1As6/bAMQiDiwT9OZ7xg',512,1,4,VERSION_13));
var_dump(argon2d_password_hash_need_rehash('$argon2d$v=19$m=512,t=4,p=4$NThzRmFWUlZNNjhYM3FLeQ$qrvsv71DIzPwIy/ZWUM7B6M1As6/bAMQiDiwT9OZ7xg',512,1,4,VERSION_13));
var_dump(argon2d_password_hash_need_rehash('$argon2d$v=19$m=512,t=5,p=4$NThzRmFWUlZNNjhYM3FLeQ$qrvsv71DIzPwIy/ZWUM7B6M1As6/bAMQiDiwT9OZ7xg',512,1,4,VERSION_13));
var_dump(argon2d_password_hash_need_rehash('$argon2d$v=19$m=512,t=6,p=4$NThzRmFWUlZNNjhYM3FLeQ$qrvsv71DIzPwIy/ZWUM7B6M1As6/bAMQiDiwT9OZ7xg',512,1,4,VERSION_13));
var_dump(argon2d_password_hash_need_rehash('$argon2d$v=19$m=512,t=7,p=4$NThzRmFWUlZNNjhYM3FLeQ$qrvsv71DIzPwIy/ZWUM7B6M1As6/bAMQiDiwT9OZ7xg',512,1,4,VERSION_13));
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)

