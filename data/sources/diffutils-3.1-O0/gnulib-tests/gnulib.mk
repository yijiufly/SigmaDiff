## DO NOT EDIT! GENERATED AUTOMATICALLY!
## Process this file with automake to produce Makefile.in.
# Copyright (C) 2002-2011 Free Software Foundation, Inc.
#
# This file is free software, distributed under the terms of the GNU
# General Public License.  As a special exception to the GNU General
# Public License, this file may be distributed as part of a program
# that contains a configuration script generated by Autoconf, under
# the same distribution terms as the rest of that program.
#
# Generated by gnulib-tool.

AUTOMAKE_OPTIONS = 1.5 foreign subdir-objects

SUBDIRS = .
TESTS =
XFAIL_TESTS =
TESTS_ENVIRONMENT =
noinst_PROGRAMS =
check_PROGRAMS =
noinst_HEADERS =
noinst_LIBRARIES =
check_LIBRARIES = libtests.a
EXTRA_DIST =
BUILT_SOURCES =
SUFFIXES =
MOSTLYCLEANFILES = core *.stackdump
MOSTLYCLEANDIRS =
CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =

AM_CPPFLAGS = \
  -D@gltests_WITNESS@=1 \
  -I. -I$(srcdir) \
  -I.. -I$(srcdir)/.. \
  -I../lib -I$(srcdir)/../lib

LDADD = libtests.a ../lib/libdiffutils.a libtests.a $(LIBTESTS_LIBDEPS)

libtests_a_SOURCES =
libtests_a_LIBADD = $(gltests_LIBOBJS)
libtests_a_DEPENDENCIES = $(gltests_LIBOBJS)
EXTRA_libtests_a_SOURCES =
AM_LIBTOOLFLAGS = --preserve-dup-deps

TESTS_ENVIRONMENT += EXEEXT='@EXEEXT@' srcdir='$(srcdir)'

## begin gnulib module alloca-opt-tests

TESTS += test-alloca-opt
check_PROGRAMS += test-alloca-opt

EXTRA_DIST += test-alloca-opt.c

## end   gnulib module alloca-opt-tests

## begin gnulib module argmatch

libtests_a_SOURCES += argmatch.c

EXTRA_DIST += argmatch.h

## end   gnulib module argmatch

## begin gnulib module argmatch-tests

TESTS += test-argmatch
check_PROGRAMS += test-argmatch
test_argmatch_LDADD = $(LDADD) @LIBINTL@

EXTRA_DIST += test-argmatch.c macros.h

## end   gnulib module argmatch-tests

## begin gnulib module binary-io

libtests_a_SOURCES += binary-io.h

## end   gnulib module binary-io

## begin gnulib module binary-io-tests

TESTS += test-binary-io.sh
check_PROGRAMS += test-binary-io

EXTRA_DIST += test-binary-io.sh test-binary-io.c macros.h

## end   gnulib module binary-io-tests

## begin gnulib module bitrotate-tests

TESTS += test-bitrotate
check_PROGRAMS += test-bitrotate
EXTRA_DIST += test-bitrotate.c macros.h

## end   gnulib module bitrotate-tests

## begin gnulib module btowc-tests

TESTS += test-btowc1.sh test-btowc2.sh
TESTS_ENVIRONMENT += LOCALE_FR='@LOCALE_FR@' LOCALE_FR_UTF8='@LOCALE_FR_UTF8@'
check_PROGRAMS += test-btowc

EXTRA_DIST += test-btowc1.sh test-btowc2.sh test-btowc.c signature.h macros.h

## end   gnulib module btowc-tests

## begin gnulib module c-ctype-tests

TESTS += test-c-ctype
check_PROGRAMS += test-c-ctype

EXTRA_DIST += test-c-ctype.c macros.h

## end   gnulib module c-ctype-tests

## begin gnulib module c-stack-tests

TESTS += test-c-stack.sh test-c-stack2.sh
TESTS_ENVIRONMENT += LIBSIGSEGV='@LIBSIGSEGV@'
check_PROGRAMS += test-c-stack
test_c_stack_LDADD = $(LDADD) $(LIBCSTACK) @LIBINTL@
MOSTLYCLEANFILES += t-c-stack.tmp t-c-stack2.tmp
EXTRA_DIST += test-c-stack.c test-c-stack.sh test-c-stack2.sh macros.h

## end   gnulib module c-stack-tests

## begin gnulib module c-strcase-tests

TESTS += test-c-strcase.sh
TESTS_ENVIRONMENT += LOCALE_FR='@LOCALE_FR@' LOCALE_TR_UTF8='@LOCALE_TR_UTF8@'
check_PROGRAMS += test-c-strcasecmp test-c-strncasecmp
EXTRA_DIST += test-c-strcase.sh test-c-strcasecmp.c test-c-strncasecmp.c macros.h

## end   gnulib module c-strcase-tests

## begin gnulib module dirname-tests

TESTS += test-dirname
check_PROGRAMS += test-dirname
test_dirname_LDADD = $(LDADD) @LIBINTL@
EXTRA_DIST += test-dirname.c

## end   gnulib module dirname-tests

## begin gnulib module dup2-tests

TESTS += test-dup2
check_PROGRAMS += test-dup2
EXTRA_DIST += test-dup2.c signature.h macros.h

## end   gnulib module dup2-tests

## begin gnulib module environ-tests

TESTS += test-environ
check_PROGRAMS += test-environ

EXTRA_DIST += test-environ.c

## end   gnulib module environ-tests

## begin gnulib module errno-tests

TESTS += test-errno
check_PROGRAMS += test-errno

EXTRA_DIST += test-errno.c

## end   gnulib module errno-tests

## begin gnulib module exclude-tests

TESTS += \
 test-exclude1.sh\
 test-exclude2.sh\
 test-exclude3.sh\
 test-exclude4.sh\
 test-exclude5.sh\
 test-exclude6.sh\
 test-exclude7.sh\
 test-exclude8.sh

check_PROGRAMS += test-exclude
test_exclude_LDADD = $(LDADD) @LIBINTL@
EXTRA_DIST += test-exclude.c test-exclude1.sh test-exclude2.sh test-exclude3.sh test-exclude4.sh test-exclude5.sh test-exclude6.sh test-exclude7.sh test-exclude8.sh

## end   gnulib module exclude-tests

## begin gnulib module fcntl-h-tests

TESTS += test-fcntl-h
check_PROGRAMS += test-fcntl-h
EXTRA_DIST += test-fcntl-h.c

## end   gnulib module fcntl-h-tests

## begin gnulib module fcntl-tests

TESTS += test-fcntl
check_PROGRAMS += test-fcntl
EXTRA_DIST += test-fcntl.c signature.h macros.h

## end   gnulib module fcntl-tests

## begin gnulib module filenamecat-tests

TESTS += test-filenamecat
check_PROGRAMS += test-filenamecat
test_filenamecat_LDADD = $(LDADD) @LIBINTL@
EXTRA_DIST += test-filenamecat.c

## end   gnulib module filenamecat-tests

## begin gnulib module float

BUILT_SOURCES += $(FLOAT_H)

# We need the following in order to create <float.h> when the system
# doesn't have one that works with the given compiler.
if GL_GENERATE_FLOAT_H
float.h: float.in.h $(top_builddir)/config.status
	$(AM_V_GEN)rm -f $@-t $@ && \
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */' && \
	  sed -e 's|@''GUARD_PREFIX''@|GL|g' \
	      -e 's|@''INCLUDE_NEXT''@|$(INCLUDE_NEXT)|g' \
	      -e 's|@''PRAGMA_SYSTEM_HEADER''@|@PRAGMA_SYSTEM_HEADER@|g' \
	      -e 's|@''PRAGMA_COLUMNS''@|@PRAGMA_COLUMNS@|g' \
	      -e 's|@''NEXT_FLOAT_H''@|$(NEXT_FLOAT_H)|g' \
	      < $(srcdir)/float.in.h; \
	} > $@-t && \
	mv $@-t $@
else
float.h: $(top_builddir)/config.status
	rm -f $@
endif
MOSTLYCLEANFILES += float.h float.h-t

EXTRA_DIST += float.c float.in.h

EXTRA_libtests_a_SOURCES += float.c

## end   gnulib module float

## begin gnulib module float-tests

TESTS += test-float
check_PROGRAMS += test-float
EXTRA_DIST += test-float.c macros.h

## end   gnulib module float-tests

## begin gnulib module fnmatch-tests

TESTS += test-fnmatch
check_PROGRAMS += test-fnmatch
EXTRA_DIST += test-fnmatch.c signature.h macros.h

## end   gnulib module fnmatch-tests

## begin gnulib module fpucw


EXTRA_DIST += fpucw.h

## end   gnulib module fpucw

## begin gnulib module freopen-safer-tests

TESTS += test-freopen-safer
check_PROGRAMS += test-freopen-safer
EXTRA_DIST += test-freopen-safer.c macros.h

## end   gnulib module freopen-safer-tests

## begin gnulib module freopen-tests

TESTS += test-freopen
check_PROGRAMS += test-freopen

EXTRA_DIST += test-freopen.c signature.h macros.h

## end   gnulib module freopen-tests

## begin gnulib module getcwd-lgpl


EXTRA_DIST += getcwd-lgpl.c

EXTRA_libtests_a_SOURCES += getcwd-lgpl.c

## end   gnulib module getcwd-lgpl

## begin gnulib module getcwd-lgpl-tests

TESTS += test-getcwd-lgpl
check_PROGRAMS += test-getcwd-lgpl
EXTRA_DIST += test-getcwd-lgpl.c signature.h macros.h

## end   gnulib module getcwd-lgpl-tests

## begin gnulib module getdtablesize-tests

TESTS += test-getdtablesize
check_PROGRAMS += test-getdtablesize
EXTRA_DIST += test-getdtablesize.c signature.h macros.h

## end   gnulib module getdtablesize-tests

## begin gnulib module getopt-posix-tests

TESTS += test-getopt
check_PROGRAMS += test-getopt
test_getopt_LDADD = $(LDADD) $(LIBINTL)
EXTRA_DIST += macros.h signature.h test-getopt.c test-getopt.h test-getopt_long.h

## end   gnulib module getopt-posix-tests

## begin gnulib module getpagesize


EXTRA_DIST += getpagesize.c

EXTRA_libtests_a_SOURCES += getpagesize.c

## end   gnulib module getpagesize

## begin gnulib module gettimeofday-tests

TESTS += test-gettimeofday
check_PROGRAMS += test-gettimeofday

EXTRA_DIST += signature.h test-gettimeofday.c

## end   gnulib module gettimeofday-tests

## begin gnulib module hash-pjw

libtests_a_SOURCES += hash-pjw.h hash-pjw.c

## end   gnulib module hash-pjw

## begin gnulib module hash-tests

TESTS += test-hash
check_PROGRAMS += test-hash
EXTRA_DIST += test-hash.c macros.h

## end   gnulib module hash-tests

## begin gnulib module iconv-h-tests

TESTS += test-iconv-h
check_PROGRAMS += test-iconv-h
EXTRA_DIST += test-iconv-h.c

## end   gnulib module iconv-h-tests

## begin gnulib module iconv-tests

TESTS += test-iconv
check_PROGRAMS += test-iconv
test_iconv_LDADD = $(LDADD) @LIBICONV@

EXTRA_DIST += test-iconv.c signature.h macros.h

## end   gnulib module iconv-tests

## begin gnulib module ignore-value-tests

TESTS += test-ignore-value
check_PROGRAMS += test-ignore-value
EXTRA_DIST += test-ignore-value.c

## end   gnulib module ignore-value-tests

## begin gnulib module intprops-tests

TESTS += test-intprops
check_PROGRAMS += test-intprops
EXTRA_DIST += test-intprops.c macros.h

## end   gnulib module intprops-tests

## begin gnulib module inttostr-tests

TESTS += test-inttostr
check_PROGRAMS += test-inttostr
EXTRA_DIST += macros.h test-inttostr.c

## end   gnulib module inttostr-tests

## begin gnulib module inttypes-tests

TESTS += test-inttypes
check_PROGRAMS += test-inttypes
EXTRA_DIST += test-inttypes.c

## end   gnulib module inttypes-tests

## begin gnulib module iswblank-tests

TESTS += test-iswblank
check_PROGRAMS += test-iswblank
EXTRA_DIST += test-iswblank.c macros.h

## end   gnulib module iswblank-tests

## begin gnulib module langinfo-tests

TESTS += test-langinfo
check_PROGRAMS += test-langinfo
EXTRA_DIST += test-langinfo.c

## end   gnulib module langinfo-tests

## begin gnulib module locale

BUILT_SOURCES += locale.h

# We need the following in order to create <locale.h> when the system
# doesn't have one that provides all definitions.
locale.h: locale.in.h $(top_builddir)/config.status $(CXXDEFS_H) $(ARG_NONNULL_H) $(WARN_ON_USE_H)
	$(AM_V_GEN)rm -f $@-t $@ && \
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */' && \
	  sed -e 's|@''GUARD_PREFIX''@|GL|g' \
	      -e 's|@''INCLUDE_NEXT''@|$(INCLUDE_NEXT)|g' \
	      -e 's|@''PRAGMA_SYSTEM_HEADER''@|@PRAGMA_SYSTEM_HEADER@|g' \
	      -e 's|@''PRAGMA_COLUMNS''@|@PRAGMA_COLUMNS@|g' \
	      -e 's|@''NEXT_LOCALE_H''@|$(NEXT_LOCALE_H)|g' \
	      -e 's/@''GNULIB_SETLOCALE''@/$(GNULIB_SETLOCALE)/g' \
	      -e 's/@''GNULIB_DUPLOCALE''@/$(GNULIB_DUPLOCALE)/g' \
	      -e 's|@''HAVE_DUPLOCALE''@|$(HAVE_DUPLOCALE)|g' \
	      -e 's|@''HAVE_XLOCALE_H''@|$(HAVE_XLOCALE_H)|g' \
	      -e 's|@''REPLACE_SETLOCALE''@|$(REPLACE_SETLOCALE)|g' \
	      -e 's|@''REPLACE_DUPLOCALE''@|$(REPLACE_DUPLOCALE)|g' \
	      -e '/definitions of _GL_FUNCDECL_RPL/r $(CXXDEFS_H)' \
	      -e '/definition of _GL_ARG_NONNULL/r $(ARG_NONNULL_H)' \
	      -e '/definition of _GL_WARN_ON_USE/r $(WARN_ON_USE_H)' \
	      < $(srcdir)/locale.in.h; \
	} > $@-t && \
	mv $@-t $@
MOSTLYCLEANFILES += locale.h locale.h-t

EXTRA_DIST += locale.in.h

## end   gnulib module locale

## begin gnulib module locale-tests

TESTS += test-locale
check_PROGRAMS += test-locale
EXTRA_DIST += test-locale.c

## end   gnulib module locale-tests

## begin gnulib module lstat-tests

TESTS += test-lstat
check_PROGRAMS += test-lstat
EXTRA_DIST += test-lstat.h test-lstat.c signature.h macros.h

## end   gnulib module lstat-tests

## begin gnulib module malloc-gnu-tests

TESTS += test-malloc-gnu
check_PROGRAMS += test-malloc-gnu
EXTRA_DIST += test-malloc-gnu.c

## end   gnulib module malloc-gnu-tests

## begin gnulib module malloca-tests

TESTS += test-malloca
check_PROGRAMS += test-malloca

EXTRA_DIST += test-malloca.c

## end   gnulib module malloca-tests

## begin gnulib module mbrtowc-tests

TESTS += \
  test-mbrtowc1.sh test-mbrtowc2.sh test-mbrtowc3.sh test-mbrtowc4.sh \
  test-mbrtowc-w32-1.sh test-mbrtowc-w32-2.sh test-mbrtowc-w32-3.sh \
  test-mbrtowc-w32-4.sh test-mbrtowc-w32-5.sh
TESTS_ENVIRONMENT += \
  LOCALE_FR='@LOCALE_FR@' \
  LOCALE_FR_UTF8='@LOCALE_FR_UTF8@' \
  LOCALE_JA='@LOCALE_JA@' \
  LOCALE_ZH_CN='@LOCALE_ZH_CN@'
check_PROGRAMS += test-mbrtowc test-mbrtowc-w32

EXTRA_DIST += test-mbrtowc1.sh test-mbrtowc2.sh test-mbrtowc3.sh test-mbrtowc4.sh test-mbrtowc.c test-mbrtowc-w32-1.sh test-mbrtowc-w32-2.sh test-mbrtowc-w32-3.sh test-mbrtowc-w32-4.sh test-mbrtowc-w32-5.sh test-mbrtowc-w32.c signature.h macros.h

## end   gnulib module mbrtowc-tests

## begin gnulib module mbscasecmp-tests

TESTS += test-mbscasecmp.sh
TESTS_ENVIRONMENT += LOCALE_TR_UTF8='@LOCALE_TR_UTF8@'
check_PROGRAMS += test-mbscasecmp

EXTRA_DIST += test-mbscasecmp.sh test-mbscasecmp.c macros.h

## end   gnulib module mbscasecmp-tests

## begin gnulib module mbsinit-tests

TESTS += test-mbsinit.sh
TESTS_ENVIRONMENT += LOCALE_FR_UTF8='@LOCALE_FR_UTF8@'
check_PROGRAMS += test-mbsinit

EXTRA_DIST += test-mbsinit.sh test-mbsinit.c signature.h macros.h

## end   gnulib module mbsinit-tests

## begin gnulib module mbsrtowcs-tests

TESTS += test-mbsrtowcs1.sh test-mbsrtowcs2.sh test-mbsrtowcs3.sh test-mbsrtowcs4.sh
TESTS_ENVIRONMENT += \
  LOCALE_FR='@LOCALE_FR@' \
  LOCALE_FR_UTF8='@LOCALE_FR_UTF8@' \
  LOCALE_JA='@LOCALE_JA@' \
  LOCALE_ZH_CN='@LOCALE_ZH_CN@'
check_PROGRAMS += test-mbsrtowcs

EXTRA_DIST += test-mbsrtowcs1.sh test-mbsrtowcs2.sh test-mbsrtowcs3.sh test-mbsrtowcs4.sh test-mbsrtowcs.c signature.h macros.h

## end   gnulib module mbsrtowcs-tests

## begin gnulib module mbsstr-tests

TESTS += test-mbsstr1 test-mbsstr2.sh test-mbsstr3.sh
TESTS_ENVIRONMENT += LOCALE_FR_UTF8='@LOCALE_FR_UTF8@' LOCALE_ZH_CN='@LOCALE_ZH_CN@'
check_PROGRAMS += test-mbsstr1 test-mbsstr2 test-mbsstr3

EXTRA_DIST += test-mbsstr1.c test-mbsstr2.sh test-mbsstr2.c test-mbsstr3.sh test-mbsstr3.c macros.h

## end   gnulib module mbsstr-tests

## begin gnulib module memchr-tests

TESTS += test-memchr
check_PROGRAMS += test-memchr
EXTRA_DIST += test-memchr.c zerosize-ptr.h signature.h macros.h

## end   gnulib module memchr-tests

## begin gnulib module nl_langinfo-tests

TESTS += test-nl_langinfo.sh
TESTS_ENVIRONMENT += LOCALE_FR='@LOCALE_FR@' LOCALE_FR_UTF8='@LOCALE_FR_UTF8@'
check_PROGRAMS += test-nl_langinfo
EXTRA_DIST += test-nl_langinfo.sh test-nl_langinfo.c signature.h macros.h

## end   gnulib module nl_langinfo-tests

## begin gnulib module open-tests

TESTS += test-open
check_PROGRAMS += test-open
EXTRA_DIST += test-open.h test-open.c signature.h macros.h

## end   gnulib module open-tests

## begin gnulib module putenv


EXTRA_DIST += putenv.c

EXTRA_libtests_a_SOURCES += putenv.c

## end   gnulib module putenv

## begin gnulib module quotearg-simple-tests

TESTS += test-quotearg-simple
check_PROGRAMS += test-quotearg-simple
test_quotearg_simple_LDADD = $(LDADD) @LIBINTL@
EXTRA_DIST += test-quotearg-simple.c test-quotearg.h macros.h

## end   gnulib module quotearg-simple-tests

## begin gnulib module same-inode


EXTRA_DIST += same-inode.h

## end   gnulib module same-inode

## begin gnulib module setenv


EXTRA_DIST += setenv.c

EXTRA_libtests_a_SOURCES += setenv.c

## end   gnulib module setenv

## begin gnulib module setenv-tests

TESTS += test-setenv
check_PROGRAMS += test-setenv
EXTRA_DIST += test-setenv.c signature.h macros.h

## end   gnulib module setenv-tests

## begin gnulib module setlocale


EXTRA_DIST += setlocale.c

EXTRA_libtests_a_SOURCES += setlocale.c

## end   gnulib module setlocale

## begin gnulib module setlocale-tests

TESTS += test-setlocale1.sh test-setlocale2.sh
TESTS_ENVIRONMENT += \
  LOCALE_FR='@LOCALE_FR@' \
  LOCALE_FR_UTF8='@LOCALE_FR_UTF8@' \
  LOCALE_JA='@LOCALE_JA@' \
  LOCALE_ZH_CN='@LOCALE_ZH_CN@'
check_PROGRAMS += test-setlocale1 test-setlocale2
EXTRA_DIST += test-setlocale1.sh test-setlocale1.c test-setlocale2.sh test-setlocale2.c signature.h macros.h

## end   gnulib module setlocale-tests

## begin gnulib module sigaction-tests

TESTS += test-sigaction
check_PROGRAMS += test-sigaction
EXTRA_DIST += test-sigaction.c signature.h macros.h

## end   gnulib module sigaction-tests

## begin gnulib module signal-tests

TESTS += test-signal
check_PROGRAMS += test-signal
EXTRA_DIST += test-signal.c

## end   gnulib module signal-tests

## begin gnulib module sigprocmask-tests

TESTS += test-sigprocmask
check_PROGRAMS += test-sigprocmask
EXTRA_DIST += test-sigprocmask.c signature.h macros.h

## end   gnulib module sigprocmask-tests

## begin gnulib module size_max

libtests_a_SOURCES += size_max.h

## end   gnulib module size_max

## begin gnulib module sleep


EXTRA_DIST += sleep.c

EXTRA_libtests_a_SOURCES += sleep.c

## end   gnulib module sleep

## begin gnulib module sleep-tests

TESTS += test-sleep
check_PROGRAMS += test-sleep
EXTRA_DIST += test-sleep.c signature.h macros.h

## end   gnulib module sleep-tests

## begin gnulib module snippet/_Noreturn

# Because this Makefile snippet defines a variable used by other
# gnulib Makefile snippets, it must be present in all Makefile.am that
# need it. This is ensured by the applicability 'all' defined above.

_NORETURN_H=$(top_srcdir)/build-aux/snippet/_Noreturn.h

EXTRA_DIST += $(top_srcdir)/build-aux/snippet/_Noreturn.h

## end   gnulib module snippet/_Noreturn

## begin gnulib module snippet/arg-nonnull

# The BUILT_SOURCES created by this Makefile snippet are not used via #include
# statements but through direct file reference. Therefore this snippet must be
# present in all Makefile.am that need it. This is ensured by the applicability
# 'all' defined above.

BUILT_SOURCES += arg-nonnull.h
# The arg-nonnull.h that gets inserted into generated .h files is the same as
# build-aux/snippet/arg-nonnull.h, except that it has the copyright header cut
# off.
arg-nonnull.h: $(top_srcdir)/build-aux/snippet/arg-nonnull.h
	$(AM_V_GEN)rm -f $@-t $@ && \
	sed -n -e '/GL_ARG_NONNULL/,$$p' \
	  < $(top_srcdir)/build-aux/snippet/arg-nonnull.h \
	  > $@-t && \
	mv $@-t $@
MOSTLYCLEANFILES += arg-nonnull.h arg-nonnull.h-t

ARG_NONNULL_H=arg-nonnull.h

EXTRA_DIST += $(top_srcdir)/build-aux/snippet/arg-nonnull.h

## end   gnulib module snippet/arg-nonnull

## begin gnulib module snippet/c++defs

# The BUILT_SOURCES created by this Makefile snippet are not used via #include
# statements but through direct file reference. Therefore this snippet must be
# present in all Makefile.am that need it. This is ensured by the applicability
# 'all' defined above.

BUILT_SOURCES += c++defs.h
# The c++defs.h that gets inserted into generated .h files is the same as
# build-aux/snippet/c++defs.h, except that it has the copyright header cut off.
c++defs.h: $(top_srcdir)/build-aux/snippet/c++defs.h
	$(AM_V_GEN)rm -f $@-t $@ && \
	sed -n -e '/_GL_CXXDEFS/,$$p' \
	  < $(top_srcdir)/build-aux/snippet/c++defs.h \
	  > $@-t && \
	mv $@-t $@
MOSTLYCLEANFILES += c++defs.h c++defs.h-t

CXXDEFS_H=c++defs.h

EXTRA_DIST += $(top_srcdir)/build-aux/snippet/c++defs.h

## end   gnulib module snippet/c++defs

## begin gnulib module snippet/unused-parameter

# The BUILT_SOURCES created by this Makefile snippet are not used via #include
# statements but through direct file reference. Therefore this snippet must be
# present in all Makefile.am that need it. This is ensured by the applicability
# 'all' defined above.

BUILT_SOURCES += unused-parameter.h
# The unused-parameter.h that gets inserted into generated .h files is the same
# as build-aux/snippet/unused-parameter.h, except that it has the copyright
# header cut off.
unused-parameter.h: $(top_srcdir)/build-aux/snippet/unused-parameter.h
	$(AM_V_GEN)rm -f $@-t $@ && \
	sed -n -e '/GL_UNUSED_PARAMETER/,$$p' \
	  < $(top_srcdir)/build-aux/snippet/unused-parameter.h \
	  > $@-t && \
	mv $@-t $@
MOSTLYCLEANFILES += unused-parameter.h unused-parameter.h-t

UNUSED_PARAMETER_H=unused-parameter.h

EXTRA_DIST += $(top_srcdir)/build-aux/snippet/unused-parameter.h

## end   gnulib module snippet/unused-parameter

## begin gnulib module snippet/warn-on-use

BUILT_SOURCES += warn-on-use.h
# The warn-on-use.h that gets inserted into generated .h files is the same as
# build-aux/snippet/warn-on-use.h, except that it has the copyright header cut
# off.
warn-on-use.h: $(top_srcdir)/build-aux/snippet/warn-on-use.h
	$(AM_V_GEN)rm -f $@-t $@ && \
	sed -n -e '/^.ifndef/,$$p' \
	  < $(top_srcdir)/build-aux/snippet/warn-on-use.h \
	  > $@-t && \
	mv $@-t $@
MOSTLYCLEANFILES += warn-on-use.h warn-on-use.h-t

WARN_ON_USE_H=warn-on-use.h

EXTRA_DIST += $(top_srcdir)/build-aux/snippet/warn-on-use.h

## end   gnulib module snippet/warn-on-use

## begin gnulib module snprintf


EXTRA_DIST += snprintf.c

EXTRA_libtests_a_SOURCES += snprintf.c

## end   gnulib module snprintf

## begin gnulib module snprintf-tests

TESTS += test-snprintf
check_PROGRAMS += test-snprintf

EXTRA_DIST += test-snprintf.c signature.h macros.h

## end   gnulib module snprintf-tests

## begin gnulib module stat-tests

TESTS += test-stat
check_PROGRAMS += test-stat
EXTRA_DIST += test-stat.h test-stat.c signature.h macros.h

## end   gnulib module stat-tests

## begin gnulib module stat-time-tests

TESTS += test-stat-time
check_PROGRAMS += test-stat-time
EXTRA_DIST += test-stat-time.c macros.h

## end   gnulib module stat-time-tests

## begin gnulib module stdbool-tests

TESTS += test-stdbool
check_PROGRAMS += test-stdbool
EXTRA_DIST += test-stdbool.c

## end   gnulib module stdbool-tests

## begin gnulib module stddef-tests

TESTS += test-stddef
check_PROGRAMS += test-stddef
EXTRA_DIST += test-stddef.c

## end   gnulib module stddef-tests

## begin gnulib module stdint-tests

TESTS += test-stdint
check_PROGRAMS += test-stdint
EXTRA_DIST += test-stdint.c

## end   gnulib module stdint-tests

## begin gnulib module stdio-tests

TESTS += test-stdio
check_PROGRAMS += test-stdio
EXTRA_DIST += test-stdio.c

## end   gnulib module stdio-tests

## begin gnulib module stdlib-tests

TESTS += test-stdlib
check_PROGRAMS += test-stdlib
EXTRA_DIST += test-stdlib.c test-sys_wait.h

## end   gnulib module stdlib-tests

## begin gnulib module strerror-tests

TESTS += test-strerror
check_PROGRAMS += test-strerror
EXTRA_DIST += test-strerror.c signature.h macros.h

## end   gnulib module strerror-tests

## begin gnulib module strftime-tests

TESTS += test-strftime
check_PROGRAMS += test-strftime
EXTRA_DIST += test-strftime.c macros.h

## end   gnulib module strftime-tests

## begin gnulib module striconv-tests

TESTS += test-striconv
check_PROGRAMS += test-striconv
test_striconv_LDADD = $(LDADD) @LIBICONV@

EXTRA_DIST += test-striconv.c macros.h

## end   gnulib module striconv-tests

## begin gnulib module string-tests

TESTS += test-string
check_PROGRAMS += test-string
EXTRA_DIST += test-string.c

## end   gnulib module string-tests

## begin gnulib module strings-tests

TESTS += test-strings
check_PROGRAMS += test-strings
EXTRA_DIST += test-strings.c

## end   gnulib module strings-tests

## begin gnulib module strnlen-tests

TESTS += test-strnlen
check_PROGRAMS += test-strnlen
EXTRA_DIST += test-strnlen.c zerosize-ptr.h signature.h macros.h

## end   gnulib module strnlen-tests

## begin gnulib module symlink


EXTRA_DIST += symlink.c

EXTRA_libtests_a_SOURCES += symlink.c

## end   gnulib module symlink

## begin gnulib module symlink-tests

TESTS += test-symlink
check_PROGRAMS += test-symlink
EXTRA_DIST += test-symlink.h test-symlink.c signature.h macros.h

## end   gnulib module symlink-tests

## begin gnulib module sys_stat-tests

TESTS += test-sys_stat
check_PROGRAMS += test-sys_stat
EXTRA_DIST += test-sys_stat.c

## end   gnulib module sys_stat-tests

## begin gnulib module sys_time-tests

TESTS += test-sys_time
check_PROGRAMS += test-sys_time
EXTRA_DIST += test-sys_time.c

## end   gnulib module sys_time-tests

## begin gnulib module sys_wait-tests

TESTS += test-sys_wait
check_PROGRAMS += test-sys_wait
EXTRA_DIST += test-sys_wait.c test-sys_wait.h

## end   gnulib module sys_wait-tests

## begin gnulib module time-tests

TESTS += test-time
check_PROGRAMS += test-time
EXTRA_DIST += test-time.c

## end   gnulib module time-tests

## begin gnulib module unistd-tests

TESTS += test-unistd
check_PROGRAMS += test-unistd
EXTRA_DIST += test-unistd.c

## end   gnulib module unistd-tests

## begin gnulib module unistr/u8-mbtoucr-tests

TESTS += test-u8-mbtoucr
check_PROGRAMS += test-u8-mbtoucr
test_u8_mbtoucr_SOURCES = unistr/test-u8-mbtoucr.c
test_u8_mbtoucr_LDADD = $(LDADD) $(LIBUNISTRING)
EXTRA_DIST += unistr/test-u8-mbtoucr.c macros.h

## end   gnulib module unistr/u8-mbtoucr-tests

## begin gnulib module unistr/u8-uctomb-tests

TESTS += test-u8-uctomb
check_PROGRAMS += test-u8-uctomb
test_u8_uctomb_SOURCES = unistr/test-u8-uctomb.c
test_u8_uctomb_LDADD = $(LDADD) $(LIBUNISTRING)
EXTRA_DIST += unistr/test-u8-uctomb.c macros.h

## end   gnulib module unistr/u8-uctomb-tests

## begin gnulib module uniwidth/width-tests

TESTS += test-uc_width uniwidth/test-uc_width2.sh
check_PROGRAMS += test-uc_width test-uc_width2
test_uc_width_SOURCES = uniwidth/test-uc_width.c
test_uc_width_LDADD = $(LDADD) $(LIBUNISTRING)
test_uc_width2_SOURCES = uniwidth/test-uc_width2.c
test_uc_width2_LDADD = $(LDADD) $(LIBUNISTRING)
EXTRA_DIST += uniwidth/test-uc_width.c uniwidth/test-uc_width2.c uniwidth/test-uc_width2.sh macros.h

## end   gnulib module uniwidth/width-tests

## begin gnulib module unsetenv


EXTRA_DIST += unsetenv.c

EXTRA_libtests_a_SOURCES += unsetenv.c

## end   gnulib module unsetenv

## begin gnulib module unsetenv-tests

TESTS += test-unsetenv
check_PROGRAMS += test-unsetenv
EXTRA_DIST += test-unsetenv.c signature.h macros.h

## end   gnulib module unsetenv-tests

## begin gnulib module update-copyright-tests

TESTS += test-update-copyright.sh
TESTS_ENVIRONMENT += abs_aux_dir='$(abs_aux_dir)'
EXTRA_DIST += test-update-copyright.sh

## end   gnulib module update-copyright-tests

## begin gnulib module usleep


EXTRA_DIST += usleep.c

EXTRA_libtests_a_SOURCES += usleep.c

## end   gnulib module usleep

## begin gnulib module usleep-tests

TESTS += test-usleep
check_PROGRAMS += test-usleep
EXTRA_DIST += test-usleep.c signature.h macros.h

## end   gnulib module usleep-tests

## begin gnulib module vasnprintf


EXTRA_DIST += asnprintf.c float+.h printf-args.c printf-args.h printf-parse.c printf-parse.h vasnprintf.c vasnprintf.h

EXTRA_libtests_a_SOURCES += asnprintf.c printf-args.c printf-parse.c vasnprintf.c

## end   gnulib module vasnprintf

## begin gnulib module vasnprintf-tests

TESTS += test-vasnprintf
check_PROGRAMS += test-vasnprintf

EXTRA_DIST += test-vasnprintf.c macros.h

## end   gnulib module vasnprintf-tests

## begin gnulib module vc-list-files-tests

TESTS += test-vc-list-files-git.sh
TESTS += test-vc-list-files-cvs.sh
TESTS_ENVIRONMENT += abs_aux_dir='$(abs_aux_dir)'
EXTRA_DIST += test-vc-list-files-git.sh test-vc-list-files-cvs.sh init.sh

## end   gnulib module vc-list-files-tests

## begin gnulib module verify-tests

TESTS_ENVIRONMENT += MAKE='$(MAKE)'
TESTS += test-verify test-verify.sh
check_PROGRAMS += test-verify
EXTRA_DIST += test-verify.c test-verify.sh init.sh

## end   gnulib module verify-tests

## begin gnulib module version-etc-tests

TESTS += test-version-etc.sh
check_PROGRAMS += test-version-etc
test_version_etc_LDADD = $(LDADD) @LIBINTL@
EXTRA_DIST += test-version-etc.c test-version-etc.sh

## end   gnulib module version-etc-tests

## begin gnulib module wchar-tests

TESTS += test-wchar
check_PROGRAMS += test-wchar
EXTRA_DIST += test-wchar.c

## end   gnulib module wchar-tests

## begin gnulib module wcrtomb-tests

TESTS += \
  test-wcrtomb.sh \
  test-wcrtomb-w32-1.sh test-wcrtomb-w32-2.sh test-wcrtomb-w32-3.sh \
  test-wcrtomb-w32-4.sh test-wcrtomb-w32-5.sh
TESTS_ENVIRONMENT += \
  LOCALE_FR='@LOCALE_FR@' \
  LOCALE_FR_UTF8='@LOCALE_FR_UTF8@' \
  LOCALE_JA='@LOCALE_JA@' \
  LOCALE_ZH_CN='@LOCALE_ZH_CN@'
check_PROGRAMS += test-wcrtomb test-wcrtomb-w32

EXTRA_DIST += test-wcrtomb.sh test-wcrtomb.c test-wcrtomb-w32-1.sh test-wcrtomb-w32-2.sh test-wcrtomb-w32-3.sh test-wcrtomb-w32-4.sh test-wcrtomb-w32-5.sh test-wcrtomb-w32.c signature.h macros.h

## end   gnulib module wcrtomb-tests

## begin gnulib module wctob


EXTRA_DIST += wctob.c

EXTRA_libtests_a_SOURCES += wctob.c

## end   gnulib module wctob

## begin gnulib module wctomb


EXTRA_DIST += wctomb-impl.h wctomb.c

EXTRA_libtests_a_SOURCES += wctomb.c

## end   gnulib module wctomb

## begin gnulib module wctype-h-tests

TESTS += test-wctype-h
check_PROGRAMS += test-wctype-h
EXTRA_DIST += test-wctype-h.c macros.h

## end   gnulib module wctype-h-tests

## begin gnulib module wcwidth-tests

TESTS += test-wcwidth
check_PROGRAMS += test-wcwidth

EXTRA_DIST += test-wcwidth.c signature.h macros.h

## end   gnulib module wcwidth-tests

## begin gnulib module xalloc-die-tests

TESTS += test-xalloc-die.sh
check_PROGRAMS += test-xalloc-die
test_xalloc_die_LDADD = $(LDADD) @LIBINTL@
EXTRA_DIST += test-xalloc-die.c test-xalloc-die.sh init.sh

## end   gnulib module xalloc-die-tests

## begin gnulib module xsize

libtests_a_SOURCES += xsize.h

## end   gnulib module xsize

## begin gnulib module xstrtol-tests

TESTS += test-xstrtol.sh
check_PROGRAMS += test-xstrtol test-xstrtoul
test_xstrtol_LDADD = $(LDADD) @LIBINTL@
test_xstrtoul_LDADD = $(LDADD) @LIBINTL@
EXTRA_DIST += init.sh test-xstrtol.c test-xstrtoul.c test-xstrtol.sh

## end   gnulib module xstrtol-tests

## begin gnulib module xstrtoumax-tests

TESTS += test-xstrtoumax.sh
check_PROGRAMS += test-xstrtoumax
test_xstrtoumax_LDADD = $(LDADD) @LIBINTL@
EXTRA_DIST += init.sh test-xstrtoumax.c test-xstrtoumax.sh

## end   gnulib module xstrtoumax-tests

# Clean up after Solaris cc.
clean-local:
	rm -rf SunWS_cache

mostlyclean-local: mostlyclean-generic
	@for dir in '' $(MOSTLYCLEANDIRS); do \
	  if test -n "$$dir" && test -d $$dir; then \
	    echo "rmdir $$dir"; rmdir $$dir; \
	  fi; \
	done; \
	:
