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

#ifndef _DBWRAP_SQLITE_H
#define _DBWRAP_SQLITE_H

#include <stdbool.h>

#include <pthread.h>

#include <sys/queue.h>

#include <sqlite3.h>

#define DBWRAP_SQLITE_VERSION	0
#define DBWRAP_SQLITE_INTERNAL_INIT	1

typedef enum _dbwrap_sqlite_column_type {
	DBWRAP_SQLITE_COLUMN_UNKNOWN = 0,
	DBWRAP_SQLITE_COLUMN_TEXT = 1,
	DBWRAP_SQLITE_COLUMN_INT = 2,
	DBWRAP_SQLITE_COLUMN_INT64 = 3,
	DBWRAP_SQLITE_COLUMN_NULL = 4,
	DBWRAP_SQLITE_COLUMN_DOUBLE = 5,
	DBWRAP_SQLITE_COLUMN_BLOB = 6,
} dbwrap_sqlite_column_type_t;

typedef struct _dbwrap_sqlite_ctx {
	uint64_t	 dsc_version;
	uint64_t	 dsc_flags;
	uint64_t	 dsc_internal_flags;
	char		*dsc_path;
	pthread_mutex_t	 dsc_mtx;
	sqlite3		*dsc_ctx;
} dbwrap_sqlite_ctx_t;

typedef struct _dbwrap_sqlite_column {
	dbwrap_sqlite_column_type_t		 dsc_type;
	void					*dsc_value;
	size_t					 dsc_size;
	LIST_ENTRY(_dbwrap_sqlite_column)	 dsc_entry;
} dbwrap_sqlite_column_t;

typedef struct _dbwrap_sqlite_row {
	dbwrap_sqlite_column_t			*dsr_tail;
	LIST_HEAD(,_dbwrap_sqlite_column)	 dsr_columns;
	LIST_ENTRY(_dbwrap_sqlite_row)		 dsr_entry;
} dbwrap_sqlite_row_t;

typedef struct _dbwrap_sqlite_query {
	uint64_t			 dsq_flags;
	char				*dsq_query;
	dbwrap_sqlite_ctx_t		*dsq_ctx;
	sqlite3_stmt			*dsq_stmt;
	size_t				 dsq_ncolumns;
	LIST_HEAD(,_dbwrap_sqlite_row)	 dsq_rows;
} dbwrap_sqlite_query_t;

dbwrap_sqlite_ctx_t *dbwrap_sqlite_ctx_new(const char *, uint64_t);
void dbwrap_sqlite_ctx_free(dbwrap_sqlite_ctx_t **);

dbwrap_sqlite_query_t *dbwrap_sqlite_query_new(dbwrap_sqlite_ctx_t *,
    const char *, uint64_t);
void dbwrap_sqlite_query_free(dbwrap_sqlite_query_t **);

bool dbwrap_sqlite_bind_int(dbwrap_sqlite_query_t *, int, int);
bool dbwrap_sqlite_bind_string(dbwrap_sqlite_query_t *, int, const char *);
bool dbwrap_sqlite_bind_blob(dbwrap_sqlite_query_t *, int, void *, size_t);

bool dbwrap_sqlite_query_exec(dbwrap_sqlite_query_t *);
bool dbwrap_sqlite_add_row(dbwrap_sqlite_query_t *);
void dbwrap_sqlite_row_free(dbwrap_sqlite_row_t **);

void dbwrap_sqlite_column_free(dbwrap_sqlite_column_t **);

#endif /* !_DBWRAP_SQLITE_H */
