AM_CFLAGS = -I$(top_srcdir)/include $(libfwkeyfetch_CFLAGS) $(libgeneral_CFLAGS) $(libimg4tool_CFLAGS) $(libimg3tool_CFLAGS) $(libpatchfinder_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(libfwkeyfetch_LIBS) $(libgeneral_LIBS) $(libimg4tool_LIBS) $(libimg3tool_LIBS) $(libpatchfinder_LIBS)


if WITH_TXMPATCHER

bin_PROGRAMS = txmPatcher

txmPatcher_CFLAGS = $(AM_CFLAGS)
txmPatcher_CXXFLAGS = $(AM_CXXFLAGS)
txmPatcher_LDFLAGS = $(AM_LDFLAGS)
txmPatcher_LDADD = ../../ra1nsn0w/libra1nsn0w.la
txmPatcher_SOURCES = 	main.cpp

endif #WITH_TXMPATCHER