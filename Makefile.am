AM_CFLAGS    = -Wall -std=c99
bin_PROGRAMS = stt runsctptest
runsctptest_SOURCES = runsctptest.c
stt_SOURCES  = addresses.h addresses.c \
               cause.h cause.c \
               checksum.h checksum.c \
               chunk.h chunk.c \
               common_header.h common_header.c \
               parameter.h parameter.c \
               tlv.h tlv.c \
               common.h \
               testtool.c
stt_LDADD    = $(GUILE_LIBS)
stt_CFLAGS   = $(GUILE_CFLAGS)
EXTRA_DIST   = init.scm quickref.txt
install-exec-hook:
	chown root $(bindir)/stt
	chmod u+s $(bindir)/stt
	@if test ! -d "$(prefix)/share/stt"; then \
  	  mkdir $(prefix)/share/stt; \
	fi
	cp $(srcdir)/init.scm $(prefix)/share/stt/init.scm

