--TEST--
Tests argon2d_password_hash_verify exceptions
--FILE--
<?php
try {
    argon2d_password_hash_verify('$argon2id$v=19$m=65536,t=3,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o','password');
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_verify('$argon2i$v=19$m=65536,t=3,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o','password');
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_verify('$argon2idv=19$m=65536,t=3,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o','password');
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_verify('$argon2d$v=0-$m=65536,t=3,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o','password');
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_verify('$argon2d$v=0$m=-1,t=3,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o','password');
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_verify('$argon2d$v=0$m=65536,t=-1,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o','password');
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_verify('$argon2d$v=0$m=65536,t=3,p=-1$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o','password');
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_verify('$argon2d$v=19$m=65536,t=3,p=4$','password');
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}

--EXPECT--
string(63) "Input is not a valid argon2d password hash in PHC string format"
string(63) "Input is not a valid argon2d password hash in PHC string format"
string(63) "Input is not a valid argon2d password hash in PHC string format"
string(63) "Input is not a valid argon2d password hash in PHC string format"
string(63) "Input is not a valid argon2d password hash in PHC string format"
string(63) "Input is not a valid argon2d password hash in PHC string format"
string(63) "Input is not a valid argon2d password hash in PHC string format"
string(63) "Input is not a valid argon2d password hash in PHC string format"
