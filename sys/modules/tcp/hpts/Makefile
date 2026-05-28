.PATH: ${SRCTOP}/sys/netinet

KMOD=   tcphpts
SRCS=   tcp_hpts.c tcp_lro_hpts.c \
	opt_inet.h opt_inet6.h opt_rss.h device_if.h bus_if.h

EVENTLOG_SCHEMA=	hpts_eventlog_schema.src

.include <bsd.kmod.mk>
