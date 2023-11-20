--TEST--
Tests argon2d_password_hash_need_rehash exceptions
--FILE--
<?php
try {
    argon2d_password_hash_need_rehash('$argon2d$v=19$m=65536,t=3,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o',-1,1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_need_rehash('$argon2d$v=19$m=65536,t=3,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o',65536,-1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_need_rehash('$argon2d$v=19$m=65536,t=3,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o',65536,1,-1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_need_rehash('$argon2d$v=19$m=65536,t=3,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o',65536,1,1,-1);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_need_rehash('$argon2i$v=19$m=65536,t=3,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o',65536,1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_need_rehash('$argon2id$v=19$m=65536,t=3,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o',65536,1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_need_rehash('$argon2d$v=19$m=65536,t=3,p=4$$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o',65536,1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_need_rehash('$argon2d$v=19$m=65536,t=3,p=4$RUlESUVJRElFD6TQaVV+h/oM3irFdXxC2nzioE4Vy9pMTi9j+5o',65536,1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_need_rehash('$argon2d$v=10$m=65536,t=3,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o',65536,1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_need_rehash('$argon2d$v=19$m=-1,t=3,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o',65536,1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_need_rehash('$argon2d$v=19$m=65536,t=-1,p=4$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o',65536,1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_need_rehash('$argon2d$v=19$m=65536,t=3,p=-1$RUlESUVJRElFSURJ$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o',65536,1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_need_rehash('$argon2d$v=19$m=65536,t=3,p=4$frfr$TInD6TQaVV+h/oM3irFdXxOC2nzioE4Vy9pMTi9j+5o',65536,1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
try {
    argon2d_password_hash_need_rehash('$argon2d$v=19$m=65536,t=3,p=4$RUlESUVJRElFSURJ$dccdcd',65536,1,1,VERSION_13);
} catch (InvalidArgumentException $e) {
    var_dump($e->getMessage());
}
--EXPECT--
string(64) "Memory must be in the value range from (8*parallelism) to 2^32-1"
string(54) "Iterations must be in the value range from 1 to 2^32-1"
string(52) "Parallelism must be in the value range from 1 to 255"
string(40) "Version must be VERSION_13 or VERSION_10"
string(57) "Error no valid argon2d password hash in PHC string format"
string(57) "Error no valid argon2d password hash in PHC string format"
string(57) "Error no valid argon2d password hash in PHC string format"
string(57) "Error no valid argon2d password hash in PHC string format"
string(79) "Error no valid password hash in PHC string format. The version must be 16 or 19"
string(116) "Error no valid password hash in PHC string format. The memory must in the value range from (8*parallelism) to 2^32-1"
string(109) "Error no valid password hash in PHC string format. The iterations must be in the value range from 1 to 2^32-1"
string(107) "Error no valid password hash in PHC string format. The parallelism must be in the value range from 1 to 255"
string(113) "Error no valid password hash in PHC string format. The base64 salt must be in the value range from 11 to 64 bytes"
string(119) "Error no valid password hash in PHC string format. The base64 tag length must be in the value range from 16 to 86 bytes"
