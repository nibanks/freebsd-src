.include <src.opts.mk>

PACKAGE=	runtime

LIB=		elog_source_lines
SHLIB_MAJOR=	1

SRCS=		libelog_source_lines.c
INCS=		libelog_source_lines.h

LIBADD=		elf dwarf

# libdwarf is built in this same lib/ pass and is not installed into the
# build sysroot until that pass finishes. Point -ldwarf at its objdir.
LDFLAGS+=	-L${.OBJDIR}/../libdwarf

CFLAGS+=	-I${SRCTOP}/sys

.include <bsd.lib.mk>
