# Shared eventlog producer-header generation for the kernel and modules.
#
# Headers are produced through ordinary make dependency rules (never at parse
# time), one per schema, into the local object directory.  Because each build
# writes its own ${.OBJDIR}/eventlog/<provider>_eventlog.h, parallel module
# builds that share a schema no longer race on a single output file.
#
# Set before including:
#
#   EVENTLOG_SCHEMAS	Schema file names (e.g. tcp_eventlog_schema.src) found
#			in EVENTLOG_SCHEMA_DIR.
#
# Optional:
#
#   EVENTLOG_SCHEMA_DIR	Directory holding the schemas and eventlog_gen.awk.
#			[${SRCTOP}/include/eventlog]
#   EVENTLOG_OBJDIR	Output directory. [${.OBJDIR}/eventlog]
#
# Exported for the includer to wire up:
#
#   EVENTLOG_HEADERS	Generated header paths (add to SRCS or BEFORE_DEPEND).
#   EVENTLOG_INCLUDE	-I flag so sources can #include <eventlog/...>.

.if !empty(EVENTLOG_SCHEMAS)
AWK?=			awk
EVENTLOG_SCHEMA_DIR?=	${SRCTOP}/include/eventlog
EVENTLOG_OBJDIR?=	${.OBJDIR}/eventlog
EVENTLOG_GEN=		${EVENTLOG_SCHEMA_DIR}/eventlog_gen.awk
EVENTLOG_INCLUDE=	-I${EVENTLOG_OBJDIR:H}

EVENTLOG_HEADERS=
.for _schema in ${EVENTLOG_SCHEMAS}
EVENTLOG_HEADERS+=	${EVENTLOG_OBJDIR}/${_schema:S/_eventlog_schema.src/_eventlog.h/}
${EVENTLOG_OBJDIR}/${_schema:S/_eventlog_schema.src/_eventlog.h/}: \
	${EVENTLOG_SCHEMA_DIR}/${_schema} ${EVENTLOG_GEN}
	@mkdir -p ${EVENTLOG_OBJDIR}
	${AWK} -f ${EVENTLOG_GEN} ${EVENTLOG_SCHEMA_DIR}/${_schema} -h -o ${.TARGET}
.endfor

CLEANFILES+=	${EVENTLOG_HEADERS}
.endif
