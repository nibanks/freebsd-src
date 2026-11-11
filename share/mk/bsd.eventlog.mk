# bsd.eventlog.mk - user-space eventlog producer integration.
#
# Gives userland programs and libraries the same workflow kernel modules
# get from the EVENTLOG_SCHEMA handling in sys/conf/kmod.mk: set
#
#	EVENTLOG_SCHEMA= <provider>_eventlog_schema.src
#
# in the Makefile, #include <eventlog/<provider>_eventlog.h>, and call the
# generated LOG macros.  This file generates the producer header from the
# schema, points the compiler at it, and links libeventlog (the user-space
# producer runtime).
#
# This is included automatically by bsd.prog.mk and bsd.lib.mk when
# EVENTLOG_SCHEMA is set; it must be processed before bsd.libnames.mk so
# the LIBADD below is honoured.

.if !empty(EVENTLOG_SCHEMA) && !defined(_BSD_EVENTLOG_MK_)
_BSD_EVENTLOG_MK_=	1

AWK?=			awk

EVENTLOG_SCHEMA_DIR?=	${SRCTOP}/include/eventlog
EVENTLOG_SCHEMA_PATH=	${EVENTLOG_SCHEMA_DIR}/${EVENTLOG_SCHEMA}
EVENTLOG_GEN=		${SRCTOP}/include/eventlog/eventlog_gen.awk
EVENTLOG_PROVIDER!=	${AWK} '/^PROVIDER/ {print tolower($$2); exit}' ${EVENTLOG_SCHEMA_PATH}
EVENTLOG_HEADER_DIR=	${OBJTOP}/sys/include/eventlog
EVENTLOG_HEADER_DIR:=	${EVENTLOG_HEADER_DIR:tA}
EVENTLOG_HEADER=	${EVENTLOG_PROVIDER}_eventlog.h
EVENTLOG_HEADER_PATH=	${EVENTLOG_HEADER_DIR}/${EVENTLOG_HEADER}

CLEANFILES+=		${EVENTLOG_HEADER_PATH}

# Generate the producer header at parse time so it exists for depend and
# compile, regenerating only when the schema or generator is newer.
.if !make(clean) && !make(cleandir) && !make(clobber)
_EVENTLOG_GENHDR!=	mkdir -p ${EVENTLOG_HEADER_DIR}; \
	if [ ! -f ${EVENTLOG_HEADER_PATH} ] || \
	   [ ${EVENTLOG_SCHEMA_PATH} -nt ${EVENTLOG_HEADER_PATH} ] || \
	   [ ${EVENTLOG_GEN} -nt ${EVENTLOG_HEADER_PATH} ]; then \
		cd ${SRCTOP} && ${AWK} -v outdir=${EVENTLOG_HEADER_DIR} \
		    -f ${EVENTLOG_GEN} ${EVENTLOG_SCHEMA_PATH} -h; \
	fi; echo done
.endif

# Resolve <eventlog/<provider>_eventlog.h> from the generated tree; the
# user-space producer API it relies on now comes from <sys/eventlog.h>.
CFLAGS+=		-I${EVENTLOG_HEADER_DIR:H} -I${SRCTOP}/include
CXXFLAGS+=		-I${EVENTLOG_HEADER_DIR:H} -I${SRCTOP}/include

# Link the user-space producer runtime.
LIBADD+=		eventlog

# Safety-net target and ordering against depend.
${EVENTLOG_HEADER_PATH}: ${EVENTLOG_GEN} ${EVENTLOG_SCHEMA_PATH}
	@mkdir -p ${EVENTLOG_HEADER_DIR}
	@cd ${SRCTOP} && ${AWK} -v outdir=${EVENTLOG_HEADER_DIR} \
	    -f ${EVENTLOG_GEN} ${EVENTLOG_SCHEMA_PATH} -h

beforedepend: ${EVENTLOG_HEADER_PATH}

.endif
