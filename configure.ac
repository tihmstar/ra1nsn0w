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
AC_PROG_CXX
AC_PROG_CC


# Check for operating system
AC_MSG_CHECKING([whether we need platform-specific build settings])
case $host_os in
  darwin* )
        CXXFLAGS+=" -stdlib=libc++"
        ;;
esac

CXXFLAGS+=" -std=c++11"
CFLAGS+=" -std=c11"

PKG_CHECK_MODULES(libfragmentzip, libfragmentzip >= 60)
PKG_CHECK_MODULES(libgeneral, libgeneral >= 32)
PKG_CHECK_MODULES(libimg4tool, libimg4tool >= 192)
PKG_CHECK_MODULES(libipatcher, libipatcher >= 77)
PKG_CHECK_MODULES(libirecovery, libirecovery-1.0 >= 1.0.1)
PKG_CHECK_MODULES(liboffsetfinder64, liboffsetfinder64 >= 122)
PKG_CHECK_MODULES(libplist, libplist-2.0 >= 2.2.0)
PKG_CHECK_MODULES(libzip, libzip >= 1.5.1)





AC_CONFIG_FILES([Makefile
                 ra1nsn0w/Makefile])
AC_OUTPUT

echo "
Configuration for $PACKAGE-$VERSION:
-------------------------------------------

  install prefix ..........: $prefix"

echo "  compiler ................: ${CC}

  Now type 'make' to build $PACKAGE-$VERSION,
  and then 'make install' for installation.
"
