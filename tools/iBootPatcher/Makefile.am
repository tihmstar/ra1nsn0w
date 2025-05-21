AM_CFLAGS = -I$(top_srcdir)/include $(libgeneral_CFLAGS) $(libimg4tool_CFLAGS) $(libimg3tool_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(libgeneral_LIBS) $(libimg4tool_LIBS) $(libimg3tool_LIBS)


if WITH_IBOOTPATCHER

bin_PROGRAMS = iBootPatcher

iBootPatcher_CFLAGS = $(AM_CFLAGS)
iBootPatcher_CXXFLAGS = $(AM_CXXFLAGS)
iBootPatcher_LDFLAGS = $(AM_LDFLAGS)
iBootPatcher_LDADD = ../../ra1nsn0w/libra1nsn0w.la
iBootPatcher_SOURCES = 	main.cpp

endif #WITH_IBOOTPATCHER