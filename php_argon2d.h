/* MIT License (c) 2023 Identeco */

#ifndef PHP_ARGON2D_H
# define PHP_ARGON2D_H

extern zend_module_entry argon2d_module_entry;
#define phpext_argon2d_ptr &argon2d_module_entry

#define PHP_ARGON2D_VERSION "0.0.1"
#define EXT_VERSION_13 ARGON2_VERSION_13
#define EXT_VERSION_10 ARGON2_VERSION_10
#define ARGON2_MEMORY 1<<16
#define ARGON2_ITERATIONS 3
#define ARGON2_PARALLELISM 4
#define ARGON2_SALT_LENGTH 16
#define ARGON2_TAG_LENGTH 32
#define ARGON2_SECRET_KEY_LENGTH 14
#define ARGON2_VERSION EXT_VERSION_13

# if defined(ZTS) && defined(COMPILE_DL_ARGON2D)
ZEND_TSRMLS_CACHE_EXTERN()
# endif

#endif	/* PHP_ARGON2D_H */