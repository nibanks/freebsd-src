.include <src.opts.mk>

PACKAGE=runtime
PROG=	elog
SRCS=	elog.c decode.c machine_metadata.c
MAN=	elog.1
# libmd: SHA-256 to derive a blob's schema_id (must match the kernel's, see
# eventlog_provider_create()).  libz: gzip'd capture output.  libelog_user_symbols:
# ELF symbol enumeration for -U/--user-symbols.  libelog_source_lines:
# DWARF line embedding for -L/--embed-source-lines.
LIBADD=	pthread z md elog_user_symbols elog_source_lines

# Generate machine_eventlog.h (and its decode blob) at Makefile parse time
# via bsd.eventlog.mk. elog is a consumer, not a producer, but needs the
# blob compiled in so it can synthesise machine metadata into captures.
EVENTLOG_SCHEMA=	machine_eventlog_schema.src

# elog decodes events at runtime from a provider "decode blob" (see
# sys/sys/eventlog_decode.h) fetched over the eventlog device or read back
# from a capture file; it no longer compiles in any per-provider generated
# decode code.  Only the sys headers (eventlog ioctls, decode-blob format)
# are needed at build time.  EVENTLOG_SCHEMA above also adds -I for the
# generated machine header.
CFLAGS+=	-I${SRCTOP}/sys

.include <bsd.prog.mk>
