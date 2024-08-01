AC_PREREQ([2.69])
AC_INIT([ra1nsn0w], m4_esyscmd([git rev-list --count HEAD | tr -d '\n']), [tihmstar@gmail.com])

AC_CANONICAL_SYSTEM
AC_CANONICAL_HOST
AM_PROG_LIBTOOL


AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

AC_DEFINE([VERSION_COMMIT_COUNT], "m4_esyscmd([git rev-list --count HEAD | tr -d '\n'])", [Git commit count])
AC_DEFINE([VERSION_COMMIT_SHA], "m4_esyscmd([git rev-parse HEAD | tr -d '\n'])", [Git commit sha])
AC_SUBST([VERSION_COMMIT_COUNT], ["m4_esyscmd([git rev-list --count HEAD | tr -d '\n'])"])
AC_SUBST([VERSION_COMMIT_SHA], ["m4_esyscmd([git rev-parse HEAD | tr -d '\n'])"])


# Checks for programs.
AC_PROG_CXX([clang++])
AC_PROG_CC([clang])


# Check for operating system
AC_MSG_CHECKING([whether we need platform-specific build settings])
case $host_os in
  darwin* )
        CXXFLAGS+=" -stdlib=libc++"
        ;;
  *mingw32*|*cygwin*|*msys*)
        AC_MSG_RESULT([${host_os}])
        win32=true
        LDFLAGS+=" -no-undefined"
        ;;
esac

CXXFLAGS+=" -std=c++11"
CFLAGS+=" -std=c11"
LDFLAGS+=" -lpthread"

LIBGENERAL_REQUIRES_STR="libgeneral >= 75"
LIBFRAGMENTZIP_REQUIRES_STR="libfragmentzip >= 67"
LIBIMG4TOOL_REQUIRES_STR="libimg4tool >= 202"
LIBIMG3TOOL_REQUIRES_STR="libimg3tool >= 8"
LIBIMG1TOOL_REQUIRES_STR="libimg1tool >= 12"
LIBIPATCHER_REQUIRES_STR="libipatcher >= 89"
LIBIRECOVERY_REQUIRES_STR="libirecovery-1.0 >= 1.0.0"
LIBPATCHFINDER_REQUIRES_STR="libpatchfinder >= 153"
LIBPLIST_REQUIRES_STR="libplist-2.0 >= 2.3.0"
LIBTSSCHECKER_REQUIRES_STR="libtsschecker >= 336"
OPENSSL_REQUIRES_STR="openssl"

PKG_CHECK_MODULES(libgeneral, $LIBGENERAL_REQUIRES_STR)
PKG_CHECK_MODULES(libfragmentzip, $LIBFRAGMENTZIP_REQUIRES_STR)
PKG_CHECK_MODULES(libimg4tool, $LIBIMG4TOOL_REQUIRES_STR)
PKG_CHECK_MODULES(libimg3tool, $LIBIMG3TOOL_REQUIRES_STR)
PKG_CHECK_MODULES(libipatcher, $LIBIPATCHER_REQUIRES_STR)
PKG_CHECK_MODULES(libirecovery, $LIBIRECOVERY_REQUIRES_STR)
PKG_CHECK_MODULES(libpatchfinder, $LIBPATCHFINDER_REQUIRES_STR)
PKG_CHECK_MODULES(libplist, $LIBPLIST_REQUIRES_STR)
PKG_CHECK_MODULES(libtsschecker, $LIBTSSCHECKER_REQUIRES_STR)
PKG_CHECK_MODULES(openssl, $OPENSSL_REQUIRES_STR, have_openssl=yes, have_openssl=no)
PKG_CHECK_MODULES(libimg1tool, $LIBIMG1TOOL_REQUIRES_STR, have_img1tool=yes, have_img1tool=no)

AC_SUBST([libgeneral_requires], [$LIBGENERAL_REQUIRES_STR])
AC_SUBST([libfragmentzip_requires], [$LIBFRAGMENTZIP_REQUIRES_STR])
AC_SUBST([libimg3tool_requires], [$LIBIMG3TOOL_REQUIRES_STR])
AC_SUBST([libimg4tool_requires], [$LIBIMG4TOOL_REQUIRES_STR])
AC_SUBST([libipatcher_requires], [$LIBIPATCHER_REQUIRES_STR])
AC_SUBST([libirecovery_requires], [$LIBIRECOVERY_REQUIRES_STR])
AC_SUBST([libpatchfinder_requires], [$LIBPATCHFINDER_REQUIRES_STR])
AC_SUBST([libplist_requires], [$LIBPLIST_REQUIRES_STR])
AC_SUBST([libtsschecker_requires], [$LIBTSSCHECKER_REQUIRES_STR])


AC_ARG_ENABLE([debug],
            [AS_HELP_STRING([--enable-debug],
            [enable debug build(default is no)])],
            [debug_build=true],
            [debug_build=false])

AC_ARG_ENABLE([plugins],
            [AS_HELP_STRING([--enable-plugins],
            [enable plugin support(default is no)])],
            [plugin_support=true],
            [plugin_support=false])

AC_ARG_WITH([img1tool],
            [AS_HELP_STRING([--without-img1tool],
            [do not build with img1tool @<:@default=yes@:>@])],
            [with_img1tool=no],
            [with_img1tool=yes])


if test "$debug_build" = true; then
  echo "*** Note: debug build requested ***"
  CFLAGS+=" -g -O0 -DDEBUG=1"
  CXXFLAGS+=" -g -O0 -DDEBUG=1"
fi

if test "x$plugin_support" == "xtrue"; then
    if test "x$enable_static" == "xyes"; then
        AC_MSG_ERROR("Cannot have plugin support with static build. Configure with '--disable-static'")
    fi
    AC_DEFINE(WITH_PLUGIN_SUPPORT, [1], [Define if you want to build with plugin support])
fi

if test "x$have_openssl" == "xyes"; then
  AC_DEFINE(HAVE_OPENSSL, [1], [Define if you have openssl])
fi
AM_CONDITIONAL([HAVE_OPENSSL], [test "x$have_openssl" = "xyes"])


if test "x$have_img1tool" == "xyes"; then
  if test "x$with_img1tool" = "xyes"; then
    AC_DEFINE(HAVE_IMG1TOOL, [1], [Define if you have img1tool])
    AC_SUBST([libimg1tool_requires], [$LIBIMG1TOOL_REQUIRES_STR])
    AC_SUBST(libimg1tool_CFLAGS)
    AC_SUBST(libimg1tool_LIBS)
  else
    echo "*** Note: img1tool has been disabled ***"
  fi
else
  if test "x$with_img1tool" == "xyes"; then
    AC_MSG_ERROR([requested building with img1tool, but library could not be found])
  fi
fi
AM_CONDITIONAL([HAVE_IMG1TOOL], [test "x$have_img1tool" = "xyes"])


# Check for functions
AC_CHECK_FUNCS([memmem asprintf strtoul_l])

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 libra1nsn0w.pc
                 ra1nsn0w/Makefile])
AC_OUTPUT

echo "
Configuration for $PACKAGE-$VERSION:
-------------------------------------------

  install prefix ..........: $prefix
  have openssl ............: $have_openssl
  have img1tool ...........: $have_img1tool
  have plugin support .....: $plugin_support"

echo "  compiler ................: ${CC}

  Now type 'make' to build $PACKAGE-$VERSION,
  and then 'make install' for installation.
"
