.include <src.opts.mk>

PACKAGE=runtime
PROG=	elog
MAN=	elog.1
LIBADD=	z

# Schema directory location
EVENTLOG_SCHEMA_DIR=	${SRCTOP}/include/eventlog

# Find all schema files (handle case where directory doesn't exist yet)
EVENTLOG_SCHEMAS!=	if [ -d ${EVENTLOG_SCHEMA_DIR} ]; then find ${EVENTLOG_SCHEMA_DIR} -name '*_eventlog_schema.src' 2>/dev/null | sed 's|.*/||' | sort; fi

# Output directory for generated consumer headers
# Use OBJTOP directly and append sys/include/eventlog
# Ensure OBJTOP is treated as absolute path (it should be, but be explicit)
EVENTLOG_HEADER_DIR=	${OBJTOP:tA}/sys/include/eventlog
EVENTLOG_CONSUMER_HEADER=	eventlog_consumer.h

# Generate consumer headers for each schema and master header
.if !empty(EVENTLOG_SCHEMAS)
EVENTLOG_CONSUMER_HEADERS_GEN=	${EVENTLOG_HEADER_DIR}/.consumer_headers_generated
CLEANFILES+=	${EVENTLOG_CONSUMER_HEADERS_GEN}
# Generate headers immediately when Makefile is parsed (for early availability)
.if !make(clean) && !make(cleandir) && !make(clobber)
_GEN_CONSUMER_HEADERS!=	${.CURDIR}/gen_eventlog_headers.sh \
	${EVENTLOG_SCHEMA_DIR} \
	${OBJTOP:tA}/sys/include/eventlog \
	${SRCTOP} \
	${SRCTOP}/include/eventlog/eventlog_gen.awk \
	${OBJTOP:tA}/sys/include/eventlog/${EVENTLOG_CONSUMER_HEADER} || true; \
	echo "consumer_headers_generated"
.endif
# Create Make targets as a safety net (immediate generation above should be sufficient)
EVENTLOG_SCHEMA_DEPS!=	if [ -d ${EVENTLOG_SCHEMA_DIR} ]; then find ${EVENTLOG_SCHEMA_DIR} -name '*_eventlog_schema.src' -type f 2>/dev/null | sort; fi
${EVENTLOG_HEADER_DIR}/${EVENTLOG_CONSUMER_HEADER}: ${SRCTOP}/include/eventlog/eventlog_gen.awk ${.CURDIR}/gen_eventlog_headers.sh ${EVENTLOG_SCHEMA_DEPS}
	${.CURDIR}/gen_eventlog_headers.sh \
		${EVENTLOG_SCHEMA_DIR} \
		${EVENTLOG_HEADER_DIR} \
		${SRCTOP} \
		${SRCTOP}/include/eventlog/eventlog_gen.awk \
		${.TARGET}
	@touch ${EVENTLOG_CONSUMER_HEADERS_GEN}

CLEANFILES+=	${EVENTLOG_HEADER_DIR}/${EVENTLOG_CONSUMER_HEADER}
clean-consumer-headers:
	@if [ -d ${EVENTLOG_HEADER_DIR} ]; then \
		for schema in ${EVENTLOG_SCHEMAS}; do \
			provider=$$(awk '/^PROVIDER/ {print tolower($$2); exit}' ${EVENTLOG_SCHEMA_DIR}/$$schema 2>/dev/null || true); \
			if [ -n "$$provider" ]; then \
				rm -f ${EVENTLOG_HEADER_DIR}/$${provider}_eventlog_consumer.h; \
			fi; \
		done; \
	fi

CFLAGS+=	-I${EVENTLOG_HEADER_DIR} -I${SRCTOP}/sys

beforebuild: ${EVENTLOG_HEADER_DIR}/${EVENTLOG_CONSUMER_HEADER}
elog.o: ${EVENTLOG_HEADER_DIR}/${EVENTLOG_CONSUMER_HEADER}
.endif

.include <bsd.prog.mk>

