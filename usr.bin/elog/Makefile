.include <src.opts.mk>

PACKAGE=runtime
PROG=	elog
MAN=	elog.1
LIBADD=	z

# Generate per-provider consumer headers and the aggregate eventlog_consumer.h
# via make dependencies (see share/mk/bsd.eventlog.mk).  The find only builds
# the schema list that drives those rules; it does not generate headers itself.
EVENTLOG_SCHEMA_DIR=	${SRCTOP}/include/eventlog
EVENTLOG_SCHEMAS!=	if [ -d ${EVENTLOG_SCHEMA_DIR} ]; then find ${EVENTLOG_SCHEMA_DIR} -name '*_eventlog_schema.src' 2>/dev/null | sed 's|.*/||' | sort; fi
.include <bsd.eventlog.mk>
.if !empty(EVENTLOG_HEADERS)
CFLAGS+=	${EVENTLOG_INCLUDE} -I${SRCTOP}/sys
beforebuild: ${EVENTLOG_HEADERS}
.endif

.include <bsd.prog.mk>

