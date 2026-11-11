.include <src.opts.mk>

PACKAGE=	lib${LIB}
LIB=		eventlog
SHLIB_MAJOR=	1

SRCS=		eventlog_user.c

# The shared staging buffer uses a pthread mutex and pthread_atfork().
LIBADD=		pthread

MAN=		eventlog_user.3
MLINKS=		eventlog_user.3 eventlog_provider_create.3 \
		eventlog_user.3 eventlog_provider_destroy.3 \
		eventlog_user.3 eventlog_provider_poll.3 \
		eventlog_user.3 eventlog_session_create.3 \
		eventlog_user.3 eventlog_session_destroy.3 \
		eventlog_user.3 eventlog_session_set_enabled.3 \
		eventlog_user.3 eventlog_session_set_filter.3 \
		eventlog_user.3 eventlog_event_write.3 \
		eventlog_user.3 eventlog_event_write_at.3 \
		eventlog_user.3 eventlog_event_write_gather.3 \
		eventlog_user.3 eventlog_event_write_gather_at.3

# The user-space producer API now lives in <sys/eventlog.h> (the !_KERNEL
# half) alongside the schema-generated <eventlog/<provider>_eventlog.h>, so
# there is no separate library header to install.

# Resolve <sys/eventlog*.h> from the source tree during our own build
# (before headers are staged into the sysroot).
CFLAGS+=	-I${SRCTOP}/include -I${SRCTOP}/sys

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CLEANFILES+=	libeventlog.pc

libeventlog.pc: libeventlog.pc.in
	sed -e 's,@prefix@,/usr,g ; \
		s,@exec_prefix@,$${prefix},g ; \
		s,@libdir@,${LIBDIR},g ; \
		s,@includedir@,${INCLUDEDIR},g ; \
		s,@VERSION@,${SHLIB_MAJOR},g ;' \
		${.ALLSRC} > ${.TARGET}

PCFILES=	libeventlog.pc

# Schema compiler, same package as the library so they stay version-paired.
.PATH:		${SRCTOP}/include/eventlog
FILES=		eventlog_gen.awk
FILESDIR=	${SHAREDIR}/eventlog

.include <bsd.lib.mk>
