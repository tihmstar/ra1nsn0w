AM_CFLAGS = $(GLOBAL_CFLAGS) $(libfragmentzip_CFLAGS) $(libgeneral_CFLAGS) $(libimg4tool_CFLAGS) $(libipatcher_CFLAGS) $(libirecovery_CFLAGS) $(liboffsetfinder64_CFLAGS) $(libplist_CFLAGS) $(libzip_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(libplist_LIBS) $(openssl_LIBS) $(libgeneral_LIBS) $(libfragmentzip_LIBS) $(libgeneral_LIBS) $(libimg4tool_LIBS) $(libipatcher_LIBS) $(libirecovery_LIBS) $(liboffsetfinder64_LIBS) $(libplist_LIBS)


bin_PROGRAMS = ra1nsn0w

ra1nsn0w_CFLAGS = $(AM_CFLAGS)
ra1nsn0w_CXXFLAGS = $(AM_CXXFLAGS)
ra1nsn0w_LDFLAGS = $(AM_LDFLAGS)
ra1nsn0w_SOURCES = 	main.cpp iOSDevice.cpp ra1nsn0w.cpp
