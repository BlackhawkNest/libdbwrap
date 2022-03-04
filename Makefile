SHLIB=		dbwrap
SHLIB_MAJOR=	0
MAN=

.PATH:		${.CURDIR}/src
.PATH:		${.CURDIR}/include

INCS+=		dbwrap_mysql.h
INCS+=		dbwrap_sqlite.h
INCS+=		dbwrap.h

SRCS+=		dbwrap_mysql.c
SRCS+=		dbwrap_sqlite.c
SRCS+=		dbwrap.c

CFLAGS+=	-D_DBWRAP_INTERNAL
CFLAGS+=	-I${.CURDIR}/include
CFLAGS+=	-I/usr/local/include

LDFLAGS+=	-L/usr/local/lib
LDFLAGS+=	-L/usr/local/lib/mysql

LDADD+=		-lmysqlclient
LDADD+=		-lsqlite3

.if defined (ASANIFY)
CFLAGS+=	-fsanitize=address
LDFLAGS+=	-fsanitize=address
.endif

.if defined(PREFIX)
LIBDIR=		${PREFIX}/lib
INCLUDEDIR=	${PREFIX}/include
.endif

.include <bsd.lib.mk>
