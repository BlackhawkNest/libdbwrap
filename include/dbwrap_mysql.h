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

#ifndef _DBWRAP_MYSQL_H
#define _DBWRAP_MYSQL_H

#include <sys/queue.h>

#include <pthread.h>

#include <mysql/mysql.h>

#define DBWRAP_MYSQL_VERSION	0

#define DBWRAP_MYSQL_FLAG_MULTI_STATEMENTS	0x1
#define DBWRAP_MYSQL_FLAG_THREAD_INIT	0x2
#define DBWRAP_MYSQL_FLAG_USE_DNS_SRV	0x4

#define DBWRAP_MYSQL_CTX_INTERNAL_FLAG_MTX_INITTED	0x1

struct _dbwrap_ctx;
struct _dbwrap_query;

typedef struct _dbwrap_mysql_ctx {
	uint64_t		 bmc_version;
	uint64_t		 bmc_flags;
	uint64_t		 bmc_internal_flags;
	MYSQL			*bmc_mysql;
	pthread_mutex_t		 bmc_mtx;
	char			*bmc_host;
	char			*bmc_password;
	char			*bmc_username;
	char			*bmc_database;
	unsigned int		 bmc_port;
	struct _dbwrap_ctx	*bmc_dbctx;
} dbwrap_mysql_ctx_t;

typedef struct _dbwrap_mysql_statement_bind {
	MYSQL_BIND					 bmsb_bind;
	LIST_ENTRY(_dbwrap_mysql_statement_bind)	 bmsb_entry;
} dbwrap_mysql_statement_bind_t;

typedef struct _dbwrap_mysql_statement {
	uint64_t					 bms_flags;
	dbwrap_mysql_ctx_t				*bms_ctx;
	char						*bms_query;
	MYSQL_STMT					*bms_statement;
	MYSQL_RES					*bms_res;
	size_t						 bms_nbinds;
	dbwrap_mysql_statement_bind_t			*bms_last;
	struct _dbwrap_query				*bms_dbquery;
	LIST_HEAD(,_dbwrap_mysql_statement_bind)	 bms_binds;
} dbwrap_mysql_statement_t;

typedef struct _dbwrap_mysql_row {
	MYSQL_BIND				*bmsb_columns;
	unsigned long				*bmsb_colsizes;
	LIST_ENTRY(_dbwrap_mysql_row)		 bmsb_entry;
} dbwrap_mysql_row_t;

typedef struct _dbwrap_mysql_statement_result {
	uint64_t				 bmsr_flags;
	size_t					 bmsr_ncols;
	dbwrap_mysql_statement_t		*bmsr_statement;
	LIST_HEAD(,_dbwrap_mysql_row)		 bmsr_rows;
} dbwrap_mysql_statement_result_t;

#ifdef __cplusplus
extern "C" {
#endif

bool dbwrap_mysql_init(void);
bool dbwrap_mysql_thread_init(void);
bool dbwrap_mysql_thread_cleanup(void);

/*
 * flags, host, username, password, database, port
 */
dbwrap_mysql_ctx_t *dbwrap_mysql_ctx_init(struct _dbwrap_ctx *, uint64_t,
    const char *, const char *, const char *, const char *, unsigned int);
void dbwrap_mysql_ctx_destroy(dbwrap_mysql_ctx_t **);
bool dbwrap_mysql_ctx_lock(dbwrap_mysql_ctx_t *);
void dbwrap_mysql_ctx_unlock(dbwrap_mysql_ctx_t *);

bool dbwrap_mysql_connect(dbwrap_mysql_ctx_t *);

dbwrap_mysql_statement_t *dbwrap_mysql_statement_init(
    struct _dbwrap_query *, dbwrap_mysql_ctx_t *, const char *, uint64_t);
void dbwrap_mysql_statement_destroy(dbwrap_mysql_statement_t **);
bool dbwrap_mysql_statement_bind(dbwrap_mysql_statement_t *,
    MYSQL_BIND *);
bool dbwrap_mysql_statement_exec(dbwrap_mysql_statement_t *);
void dbwrap_mysql_statement_free(dbwrap_mysql_statement_t **);

dbwrap_mysql_statement_result_t *dbwrap_mysql_fetch_results(
    dbwrap_mysql_statement_t *, uint64_t);
void dbwrap_mysql_statement_result_free(
    dbwrap_mysql_statement_result_t **);

#ifdef __cplusplus
}
#endif

#endif /* !_DBWRAP_MYSQL_H */
