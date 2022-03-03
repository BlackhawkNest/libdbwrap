SHLIB=		dbwrap
SHLIB_MAJOR=	0
MAN=

.PATH:		${.CURDIR}/src
.PATH:		${.CURDIR}/include

INCS+=		dbwrap_mysql.h

SRCS+=		dbwrap_mysql.c

CFLAGS+=	-I${.CURDIR}/include
CFLAGS+=	-I/usr/local/include

LDFLAGS+=	-L/usr/local/lib
LDFLAGS+=	-L/usr/local/lib/mysql

LDADD+=		-lmysqlclient
LDADD+=		-lsqlite3

.if defined(PREFIX)
LIBDIR=		${PREFIX}/lib
INCLUDEDIR=	${PREFIX}/include
.endif

.include <bsd.lib.mk>
