dnl MIT License (c) 2023 Identeco

PHP_ARG_WITH([argon2d],
  [for argon2d support],
  [AS_HELP_STRING([--with-argon2d],
    [Include argon2d support])])

if test "$PHP_ARGON2D" != "no"; then
  PATH_FOR_LIB="ext/argon2/"
  LIB_NAME="libargon2.a"
  if test -r $PATH_FOR_LIB/$LIB_NAME; then # path given as parameter
    ARGON2D_DIR=$PATH_FOR_LIB
  fi
 
  if test -z "$ARGON2D_DIR"; then
    AC_MSG_RESULT([not found libargon2.a])
    AC_MSG_ERROR([Please reinstall argon2])
  fi
  
  PHP_ADD_INCLUDE($ARGON2D_DIR)
  PHP_ADD_LIBRARY(pthread, ARGON2D_SHARED_DIR)
  
  LIBNAME=argon2
  LIBSYMBOL=argon2_hash

  PHP_CHECK_LIBRARY($LIBNAME, $LIBSYMBOL,
  [
    PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $ARGON2D_DIR, ARGON2D_SHARED_LIBADD)
    AC_DEFINE(HAVE_ARGON2, 1, [ ])
  ],[
    AC_MSG_ERROR([Problems to statically include the libargon2.a to the extension])
  ],[
    -L$ARGON2D_DIR -lrt -ldl -lpthread
  ])
  PHP_SUBST(ARGON2D_SHARED_LIBADD)
  PHP_NEW_EXTENSION(argon2d, argon2d.c, $ext_shared)
fi
