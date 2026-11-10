PACKAGE=	tests

ATF_TESTS_C+=	eventlog_user_lib_test

# The concurrency stress case spawns writer threads with pthread_create().
LIBADD.eventlog_user_lib_test+=	pthread

# The whole user-space producer integration in one line: this generates
# <eventlog/test_eventlog.h> from the kernel's own schema, points the
# compiler at it, and links libeventlog -- exactly the client workflow.
EVENTLOG_SCHEMA=	test_eventlog_schema.src

CFLAGS+=	-I${.CURDIR:H}

.include <bsd.test.mk>
