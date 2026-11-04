AM_CFLAGS = -I$(top_srcdir)/include $(libfwkeyfetch_CFLAGS) $(libgeneral_CFLAGS) $(libimg4tool_CFLAGS) $(libimg3tool_CFLAGS) $(libpatchfinder_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(libfwkeyfetch_LIBS) $(libgeneral_LIBS) $(libimg4tool_LIBS) $(libimg3tool_LIBS) $(libpatchfinder_LIBS)


if WITH_KERNELPATCHER

bin_PROGRAMS = kernelPatcher

kernelPatcher_CFLAGS = $(AM_CFLAGS)
kernelPatcher_CXXFLAGS = $(AM_CXXFLAGS)
kernelPatcher_LDFLAGS = $(AM_LDFLAGS)
kernelPatcher_LDADD = ../../ra1nsn0w/libra1nsn0w.la
kernelPatcher_SOURCES = 	main.cpp

endif #WITH_KERNELPATCHER