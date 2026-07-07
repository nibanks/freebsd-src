# Userland eventlog header generation (consumer side plus the aggregate
# routing header).  Like sys/conf/eventlog.mk, headers are produced through
# make dependency rules into the local object directory, never at parse time.
#
# Set before including:
#
#   EVENTLOG_SCHEMAS	Schema file names found in EVENTLOG_SCHEMA_DIR.
#
# Optional:
#
#   EVENTLOG_SCHEMA_DIR	Directory holding the schemas and eventlog_gen.awk.
#			[${SRCTOP}/include/eventlog]
#   EVENTLOG_OBJDIR	Output directory. [${.OBJDIR}/eventlog]
#   EVENTLOG_MASTER	Aggregate header name; empty to skip it.
#			[eventlog_consumer.h]
#
# Exported for the includer to wire up:
#
#   EVENTLOG_HEADERS	Generated header paths (add to source dependencies).
#   EVENTLOG_INCLUDE	-I flag so sources can #include "eventlog_consumer.h".

.if !empty(EVENTLOG_SCHEMAS)
AWK?=			awk
EVENTLOG_SCHEMA_DIR?=	${SRCTOP}/include/eventlog
EVENTLOG_OBJDIR?=	${.OBJDIR}/eventlog
EVENTLOG_GEN=		${EVENTLOG_SCHEMA_DIR}/eventlog_gen.awk
EVENTLOG_MASTER?=	eventlog_consumer.h
EVENTLOG_INCLUDE=	-I${EVENTLOG_OBJDIR}

EVENTLOG_HEADERS=
.for _schema in ${EVENTLOG_SCHEMAS}
EVENTLOG_HEADERS+=	${EVENTLOG_OBJDIR}/${_schema:S/_eventlog_schema.src/_eventlog_consumer.h/}
${EVENTLOG_OBJDIR}/${_schema:S/_eventlog_schema.src/_eventlog_consumer.h/}: \
	${EVENTLOG_SCHEMA_DIR}/${_schema} ${EVENTLOG_GEN}
	@mkdir -p ${EVENTLOG_OBJDIR}
	${AWK} -f ${EVENTLOG_GEN} ${EVENTLOG_SCHEMA_DIR}/${_schema} -c -o ${.TARGET}
.endfor

.if !empty(EVENTLOG_MASTER)
EVENTLOG_MASTER_HDR=	${EVENTLOG_OBJDIR}/${EVENTLOG_MASTER}
${EVENTLOG_MASTER_HDR}: ${EVENTLOG_GEN} ${EVENTLOG_HEADERS} \
	${EVENTLOG_SCHEMAS:@_s@${EVENTLOG_SCHEMA_DIR}/${_s}@}
	@mkdir -p ${EVENTLOG_OBJDIR}
	${AWK} -f ${EVENTLOG_GEN} \
	    ${EVENTLOG_SCHEMAS:@_s@${EVENTLOG_SCHEMA_DIR}/${_s}@} -M -o ${.TARGET}
EVENTLOG_HEADERS+=	${EVENTLOG_MASTER_HDR}
.endif

CLEANFILES+=	${EVENTLOG_HEADERS}
.endif
