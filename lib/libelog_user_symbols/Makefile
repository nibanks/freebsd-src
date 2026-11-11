.include <src.opts.mk>

PACKAGE=	runtime

LIB=		elog_user_symbols
SHLIB_MAJOR=	1

SRCS=		libelog_user_symbols.c
INCS=		libelog_user_symbols.h

LIBADD=		elf md

CFLAGS+=	-I${SRCTOP}/sys

.include <bsd.lib.mk>
