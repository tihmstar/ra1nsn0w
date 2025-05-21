AM_CFLAGS = -I$(top_srcdir)/include $(GLOBAL_CFLAGS) $(libfragmentzip_CFLAGS) $(libfwkeyfetch_CFLAGS) $(libgeneral_CFLAGS) $(libimg4tool_CFLAGS) $(libimg3tool_CFLAGS) $(libirecovery_CFLAGS) $(libpatchfinder_CFLAGS) $(libplist_CFLAGS) $(libtsschecker_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(libfragmentzip_LIBS) $(libfwkeyfetch_LIBS) $(libgeneral_LIBS) $(libimg4tool_LIBS) $(libimg3tool_LIBS) $(libirecovery_LIBS) $(libpatchfinder_LIBS) $(libplist_LIBS) $(libtsschecker_LIBS)


if HAVE_OPENSSL
AM_CFLAGS+=$(openssl_CFLAGS)
AM_CXXFLAGS+=$(openssl_CFLAGS)
AM_LDFLAGS+=$(openssl_LIBS)
endif

if HAVE_IMG1TOOL
AM_CFLAGS+=$(libimg1tool_CFLAGS)
AM_CXXFLAGS+=$(libimg1tool_CFLAGS)
AM_LDFLAGS+=$(libimg1tool_LIBS)
endif

bin_PROGRAMS = ra1nsn0w

ra1nsn0w_CFLAGS = $(AM_CFLAGS)
ra1nsn0w_CXXFLAGS = $(AM_CXXFLAGS)
ra1nsn0w_LDFLAGS = $(AM_LDFLAGS)

lib_LTLIBRARIES = libra1nsn0w.la

libra1nsn0w_la_CFLAGS = $(AM_CFLAGS)
libra1nsn0w_la_CXXFLAGS = $(AM_CXXFLAGS)
libra1nsn0w_la_LDFLAGS = $(AM_LDFLAGS)

ra1nsn0w_LDADD = libra1nsn0w.la
libra1nsn0w_la_SOURCES =    iOSDevice.cpp \
                            ra1nsn0w_argparser.cpp \
                            ra1nsn0w_launch.cpp \
                            ra1nsn0w_patch.cpp \
                            ra1nsn0w_plugins.cpp

ra1nsn0w_SOURCES = 	main.cpp