/* MIT License (c) 2023 Identeco */

ZEND_BEGIN_ARG_INFO_EX(arginfo_argon2d_raw_hash, 0, 0, 2)
	ZEND_ARG_INFO(0, password)
	ZEND_ARG_INFO(0, salt)
	ZEND_ARG_INFO(0, memory_kib)
	ZEND_ARG_INFO(0, iterations)
	ZEND_ARG_INFO(0, parallismen)
	ZEND_ARG_INFO(0, tag_length)
	ZEND_ARG_INFO(0, version)
	ZEND_ARG_INFO(0, secret_key)
	ZEND_ARG_INFO(0, assoziated_data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_argon2d_password_hash, 0, 0, 1)
	ZEND_ARG_INFO(0, password)
	ZEND_ARG_INFO(0, memory_kib)
	ZEND_ARG_INFO(0, iterations)
	ZEND_ARG_INFO(0, parallismen)
	ZEND_ARG_INFO(0, version)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_argon2d_password_hash_verify, 0, 0, 2)
	ZEND_ARG_INFO(0, password_hash)
	ZEND_ARG_INFO(0, password)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_argon2d_password_hash_need_rehash, 0, 0, 1)
	ZEND_ARG_INFO(0, password_hash)
	ZEND_ARG_INFO(0, memory_kib)
	ZEND_ARG_INFO(0, iterations)
	ZEND_ARG_INFO(0, parallismen)
	ZEND_ARG_INFO(0, version)
ZEND_END_ARG_INFO()


ZEND_FUNCTION(argon2d_raw_hash);
ZEND_FUNCTION(argon2d_password_hash);
ZEND_FUNCTION(argon2d_password_hash_verify);
ZEND_FUNCTION(argon2d_password_hash_need_rehash);


static const zend_function_entry ext_functions[] = {
	ZEND_FE(argon2d_raw_hash, arginfo_argon2d_raw_hash)
	ZEND_FE(argon2d_password_hash, arginfo_argon2d_password_hash)
	ZEND_FE(argon2d_password_hash_verify, arginfo_argon2d_password_hash_verify)
	ZEND_FE(argon2d_password_hash_need_rehash, arginfo_argon2d_password_hash_need_rehash)
	ZEND_FE_END
};
