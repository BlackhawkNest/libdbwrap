/*-
 * Copyright (c) 2022 BlackhawkNest, Inc
 *
 * Author: Shawn Webb <swebb@blackhawknest.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DBWRAP_H
#define _DBWRAP_H

#ifdef _DBWRAP_INTERNAL
#include "dbwrap_mysql.h"
#include "dbwrap_sqlite.h"
#else
#include <dbwrap_mysql.h>
#include <dbwrap_sqlite.h>
#endif

#define DBWRAP_VERSION 0

typedef enum _dbwrap_dbtype {
	DBWRAP_UNKNOWN=0,
	DBWRAP_MYSQL=1,
	DBWRAP_SQLITE=2,
} dbwrap_dbtype_t;

typedef struct _dbwrap_ctx {
	uint64_t			 dc_version;
	uint64_t			 dc_flags;
	dbwrap_dbtype_t			 dc_dbtype;
	union {
		dbwrap_sqlite_ctx_t	*dc_sqlite;
		dbwrap_mysql_ctx_t	*dc_mysql;
	}				 dc_dbctx;
} dbwrap_ctx_t;

typedef enum _dbwrap_column_type {
	DBWRAP_COLUMN_UNKNOWN = 0,
	DBWRAP_COLUMN_TEXT = 1,
	DBWRAP_COLUMN_INT = 2,
	DBWRAP_COLUMN_INT64 = 3,
	DBWRAP_COLUMN_NULL = 4,
	DBWRAP_COLUMN_DOUBLE = 5,
	DBWRAP_COLUMN_BLOB = 6,
} dbwrap_column_type_t;

typedef struct _dbwrap_column {
	dbwrap_column_type_t		 dc_type;
	void				*dc_value;
	size_t				 dc_size;
	LIST_ENTRY(_dbwrap_column)	 dc_entry;
} dbwrap_column_t;

typedef struct _dbwrap_row {
	dbwrap_column_t			*dr_tail;
	LIST_HEAD(,_dbwrap_column)	 dr_columns;
	LIST_ENTRY(_dbwrap_row)		 dr_entry;
} dbwrap_row_t;

typedef struct _dbwrap_query {
	uint64_t				 dq_flags;
	size_t					 dq_lastbind;
	char					*dq_query;
	dbwrap_ctx_t				*dq_ctx;
	union {
		dbwrap_sqlite_query_t		*dq_sqlite;
		dbwrap_mysql_statement_t	*dq_mysql;
	}					 dq_qobj;
	LIST_HEAD(,_dbwrap_row)			 dq_rows;
} dbwrap_query_t;

typedef struct _dbwrap_result {
	dbwrap_query_t			*dr_query;
	size_t				 dr_nrows;
	LIST_HEAD(,_dbwrap_row)		 dr_rows;
} dbwrap_result_t;

#ifdef __cplusplus
extern "C" {
#endif

dbwrap_ctx_t *dbwrap_ctx_new(dbwrap_dbtype_t, uint64_t);
bool dbwrap_ctx_sqlite_configure(dbwrap_ctx_t *, const char *, uint64_t);

/* ctx, host, username, password, database, port, flags */
bool dbwrap_ctx_mysql_configure(dbwrap_ctx_t *, const char *, const char *,
    const char *, const char *, unsigned int, uint64_t);

dbwrap_query_t *dbwrap_query_new(dbwrap_ctx_t *, const char *, uint64_t);
dbwrap_result_t *dbwrap_query_result_fetch(dbwrap_query_t *);
bool dbwrap_query_bind_int(dbwrap_query_t *, int *);
bool dbwrap_query_bind_int64(dbwrap_query_t *, long *);
bool dbwrap_query_bind_uint64(dbwrap_query_t *, unsigned long *);
bool dbwrap_query_bind_string(dbwrap_query_t *, const char *);
bool dbwrap_query_bind_blob(dbwrap_query_t *, void *, size_t);
bool dbwrap_query_exec(dbwrap_query_t *);

void dbwrap_query_free(dbwrap_query_t **);
void dbwrap_row_free(dbwrap_row_t **);
void dbwrap_column_free(dbwrap_column_t **);
void dbwrap_result_free(dbwrap_result_t **);

dbwrap_row_t *dbwrap_result_get_row(dbwrap_result_t *, size_t);
dbwrap_column_t *dbwrap_row_get_column(dbwrap_row_t *, size_t);

int dbwrap_column_to_int(dbwrap_column_t *, int);
unsigned int dbwrap_column_to_uint(dbwrap_column_t *, unsigned int);
long dbwrap_column_to_long(dbwrap_column_t *, long);
unsigned long dbwrap_column_to_ulong(dbwrap_column_t *, unsigned long);
char *dbwrap_column_to_string(dbwrap_column_t *);
void *dbwrap_column_value(dbwrap_column_t *);

#ifdef __cplusplus
}
#endif

#endif /* !_DBWRAP_H */
