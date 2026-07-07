PACKAGE=	tests
WARNS?=		6

SYSDIR?=${SRCTOP}/sys
.include "${SYSDIR}/conf/kern.opts.mk"

.PATH: ${SYSDIR}/kern

KMOD=	ktest_eventlog
SRCS=	kern_eventlog_test.c

EVENTLOG_SCHEMA=	test_eventlog_schema.src

.include <bsd.kmod.mk>

