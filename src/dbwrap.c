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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dbwrap.h"

static dbwrap_result_t *_dbwrap_convert_mysql_result(dbwrap_query_t *,
    dbwrap_mysql_statement_result_t *);
static dbwrap_result_t *_dbwrap_result_new(dbwrap_query_t *);
static dbwrap_result_t *_dbrawp_convert_sqlite_result(dbwrap_query_t *);

dbwrap_ctx_t *
dbwrap_ctx_new(dbwrap_dbtype_t dbtype, uint64_t flags)
{
	dbwrap_ctx_t *ctx;

	switch (dbtype) {
	case DBWRAP_MYSQL:
	case DBWRAP_SQLITE:
		break;
	default:
		return (NULL);
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return (ctx);
	}

	ctx->dc_flags = flags;
	ctx->dc_dbtype = dbtype;
	ctx->dc_version = DBWRAP_VERSION;

	return (ctx);
}

void
dbwrap_ctx_free(dbwrap_ctx_t **ctxp)
{
	dbwrap_ctx_t *ctx;

	if (ctxp == NULL || *ctxp == NULL) {
		return;
	}

	ctx = *ctxp;

	switch (ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		dbwrap_mysql_ctx_destroy(&(ctx->dc_dbctx.dc_mysql));
		break;
	case DBWRAP_SQLITE:
		dbwrap_sqlite_ctx_free(&(ctx->dc_dbctx.dc_sqlite));
		break;
	default:
		break;
	}

	if (ctx->dc_pool != NULL) {
		dbwrap_pool_remove_connection(ctx->dc_pool, ctx);
	}

	*ctxp = NULL;
	free(ctx);
}

dbwrap_pool_t *
dbwrap_pool_new(uint64_t flags)
{
	dbwrap_pool_t *pool;

	pool = calloc(1, sizeof(*pool));
	if (pool == NULL) {
		return (NULL);
	}

	if (pthread_mutex_init(&(pool->dp_mtx), NULL)) {
		free(pool);
		return (NULL);
	}

	pool->dp_version = DBWRAP_VERSION;
	pool->dp_flags = flags;
	LIST_INIT(&(pool->dp_conns));

	return (pool);
}

void
dbwrap_pool_free(dbwrap_pool_t **poolp, bool free_conn)
{
	dbwrap_ctx_t *ctx, *tctx;
	dbwrap_pool_t *pool;

	if (poolp == NULL || *poolp == NULL) {
		return;
	}

	pool = *poolp;

	LIST_FOREACH_SAFE(ctx, &(pool->dp_conns), dc_entry, tctx) {
		dbwrap_pool_remove_connection(pool, ctx);
		if (free_conn) {
			dbwrap_ctx_free(&ctx);
		}
	}

	pthread_mutex_destroy(&(pool->dp_mtx));
	free(pool);
	*poolp = NULL;
}

bool
dbwrap_pool_add_connection(dbwrap_pool_t *pool, dbwrap_ctx_t *ctx)
{

	if (pool == NULL || ctx == NULL) {
		return (false);
	}

	/* A given connection can be a member of only a single pool */
	if (ctx->dc_pool != NULL) {
		return (false);
	}

	if (pthread_mutex_lock(&(pool->dp_mtx))) {
		return (false);
	}

	LIST_INSERT_HEAD(&(pool->dp_conns), ctx, dc_entry);
	pool->dp_nconns++;
	ctx->dc_pool = pool;

	pthread_mutex_unlock(&(pool->dp_mtx));

	return (true);
}

void
dbwrap_pool_remove_connection(dbwrap_pool_t *pool, dbwrap_ctx_t *ctx)
{

	if (pool == NULL || ctx == NULL) {
		return;
	}

	if (ctx->dc_pool != pool) {
		return;
	}

	LIST_REMOVE(ctx, dc_entry);
	ctx->dc_pool = NULL;
}

dbwrap_ctx_t *
dbwrap_pool_get_connection(dbwrap_pool_t *pool)
{
	dbwrap_ctx_t *ctx, *tctx;
	uint64_t i;

	if (pool == NULL) {
		return (NULL);
	}

	if (pool->dp_nconns == 0) {
		return (NULL);
	}

	if (pthread_mutex_lock(&(pool->dp_mtx))) {
		return (NULL);
	}

	i = 0;
	ctx = NULL;
	LIST_FOREACH_SAFE(ctx, &(pool->dp_conns), dc_entry, tctx) {
		if (i++ == (pool->dp_lastconn % pool->dp_nconns)) {
			break;
		}
	}

	pool->dp_lastconn++;
	pthread_mutex_unlock(&(pool->dp_mtx));
	return (ctx);
}

bool
dbwrap_ctx_sqlite_configure(dbwrap_ctx_t *ctx, const char *path,
    uint64_t flags)
{

	if (ctx == NULL || ctx->dc_dbtype != DBWRAP_SQLITE) {
		return (false);
	}

	ctx->dc_dbctx.dc_sqlite = dbwrap_sqlite_ctx_new(ctx, path, flags);

	return (ctx->dc_dbctx.dc_sqlite != NULL);
}

bool
dbwrap_ctx_mysql_configure(dbwrap_ctx_t *ctx, const char *host,
    const char *username, const char *password, const char *database,
    unsigned int port, uint64_t flags)
{

	if (ctx == NULL || ctx->dc_dbtype != DBWRAP_MYSQL) {
		return (false);
	}

	ctx->dc_dbctx.dc_mysql = dbwrap_mysql_ctx_init(ctx, flags, host,
	    username, password, database, port);

	if (ctx->dc_dbctx.dc_mysql == NULL) {
		return (false);
	}

	return (dbwrap_mysql_connect(ctx->dc_dbctx.dc_mysql));
}

dbwrap_query_t *
dbwrap_query_new(dbwrap_ctx_t *ctx, const char *querystr, uint64_t flags)
{
	dbwrap_query_t *query;

	if (ctx == NULL || querystr == NULL) {
		return (NULL);
	}

	query = calloc(1, sizeof(*query));
	if (query == NULL) {
		return (NULL);
	}

	query->dq_ctx = ctx;

	switch (ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		query->dq_qobj.dq_mysql = dbwrap_mysql_statement_init(
		    query, ctx->dc_dbctx.dc_mysql, querystr, flags);
		break;
	case DBWRAP_SQLITE:
		query->dq_qobj.dq_sqlite = dbwrap_sqlite_query_new(
		    ctx->dc_dbctx.dc_sqlite, querystr, flags);
		break;
	default:
		break;
	}

	if (query->dq_qobj.dq_mysql == NULL) {
		free(query);
		return (NULL);
	}

	return (query);
}

uint64_t
dbwrap_query_get_flags(dbwrap_query_t *query)
{

	if (query == NULL) {
		return (0);
	}

	return (query->dq_flags);
}

uint64_t
dbwrap_query_set_flag(dbwrap_query_t *query, uint64_t flag)
{
	uint64_t old;

	if (query == NULL) {
		return (0);
	}

	old = query->dq_flags;
	query->dq_flags |= flag;
	return (old);
}

uint64_t
dbwrap_query_set_flags(dbwrap_query_t *query, uint64_t flags)
{
	uint64_t old;

	if (query == NULL) {
		return (0);
	}

	old = query->dq_flags;
	query->dq_flags = flags;
	return (old);
}

bool
dbwrap_query_is_flag_set(dbwrap_query_t *query, uint64_t flag)
{

	if (query == NULL) {
		return (false);
	}

	return ((query->dq_flags & flag) == flag);
}

dbwrap_errorcode_t
dbwrap_query_errorcode(dbwrap_query_t *query)
{

	if (query == NULL) {
		return (DBWRAP_ERROR_NONE);
	}

	return (query->dq_errorcode);
}

void
dbwrap_query_set_errorcode(dbwrap_query_t *query, dbwrap_errorcode_t code)
{

	if (query == NULL) {
		return;
	}

	if (code != DBWRAP_ERROR_NONE) {
		dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
	}

	query->dq_errorcode = code;
}

void
dbwrap_query_clear_errorcode(dbwrap_query_t *query)
{

	if (query == NULL) {
		return;
	}

	dbwrap_query_set_errorcode(query, DBWRAP_ERROR_NONE);
}

void
dbwrap_query_clear_error(dbwrap_query_t *query)
{

	if (query == NULL) {
		return;
	}

	dbwrap_query_clear_errorcode(query);
	if (dbwrap_query_is_flag_set(query, DBWRAP_QUERY_ERROR)) {
		dbwrap_query_set_flags(query,
		    dbwrap_query_get_flags(query) ^ DBWRAP_QUERY_ERROR);
	}
}

const char *
dbwrap_query_get_error_string(dbwrap_query_t *query) {

	if (query == NULL) {
		return ("Query object is NULL");
	}
	if (!dbwrap_query_is_flag_set(query, DBWRAP_QUERY_ERROR)) {
		return ("No error");
	}

	switch (dbwrap_query_errorcode(query)) {
	case DBWRAP_ERROR_NONE:
		return ("No error");
	case DBWRAP_ERROR_WRAP:
		return ("Generic dbwrap error");
	case DBWRAP_ERROR_TYPE:
		return ("Mismatched type error");
	case DBWRAP_ERROR_ALLOC:
		return ("Memory allocation error");
	case DBWRAP_ERROR_BACKEND:
		switch (query->dq_ctx->dc_dbtype) {
		case DBWRAP_MYSQL:
			return (mysql_stmt_error(
			    query->dq_qobj.dq_mysql->bms_statement));
		case DBWRAP_SQLITE:
			return (sqlite3_errmsg(
			    query->dq_ctx->dc_dbctx.dc_sqlite->dsc_ctx));
		default:
			return ("Unknown error");
		}
	case DBWRAP_ERROR_UNKNOWN:
	default:
		return ("Unkown error");
	}
}

unsigned int
dbwrap_query_get_errno(dbwrap_query_t *query)
{

	if (query == NULL) {
		return (0);
	}

	switch (query->dq_ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		return (mysql_stmt_errno(
		    query->dq_qobj.dq_mysql->bms_statement));
	case DBWRAP_SQLITE:
		return (sqlite3_errcode(
		    query->dq_ctx->dc_dbctx.dc_sqlite->dsc_ctx));
	default:
		return (0);
	}
}

bool
dbwrap_query_bind_int(dbwrap_query_t *query, int *val)
{
	MYSQL_BIND bval;
	bool res;

	if (query == NULL || val == NULL) {
		return (false);
	}

	memset(&bval, 0, sizeof(bval));
	switch (query->dq_ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		memset(&bval, 0, sizeof(bval));
		bval.buffer_type = MYSQL_TYPE_LONG;
		bval.buffer = val;
		res = dbwrap_mysql_statement_bind(query->dq_qobj.dq_mysql,
		    &bval);
		if (res == false) {
			dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
			dbwrap_query_set_errorcode(query,
			    DBWRAP_ERROR_BACKEND);
		}
		return (res);
	case DBWRAP_SQLITE:
		res = dbwrap_sqlite_bind_int(query->dq_qobj.dq_sqlite,
		    ++(query->dq_lastbind), *val);
		if (res == false) {
			dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
			dbwrap_query_set_errorcode(query,
			    DBWRAP_ERROR_BACKEND);
		}
		return (res);
	default:
		dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
		dbwrap_query_set_errorcode(query, DBWRAP_ERROR_WRAP);
		return (false);
	}
}

bool
dbwrap_query_bind_int64(dbwrap_query_t *query, long *val)
{
	MYSQL_BIND bval;
	bool res;

	if (query == NULL || val == NULL) {
		return (false);
	}

	memset(&bval, 0, sizeof(bval));
	switch (query->dq_ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		memset(&bval, 0, sizeof(bval));
		bval.buffer_type = MYSQL_TYPE_LONGLONG;
		bval.buffer = val;
		res = dbwrap_mysql_statement_bind(query->dq_qobj.dq_mysql,
		    &bval);
		if (res == false) {
			dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
			dbwrap_query_set_errorcode(query,
			    DBWRAP_ERROR_BACKEND);
		}
		return (res);
	case DBWRAP_SQLITE:
		res = dbwrap_sqlite_bind_int64(query->dq_qobj.dq_sqlite,
		    ++(query->dq_lastbind), *val);
		if (res == false) {
			dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
			dbwrap_query_set_errorcode(query,
			    DBWRAP_ERROR_BACKEND);
		}
		return (res);
	default:
		dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
		dbwrap_query_set_errorcode(query, DBWRAP_ERROR_WRAP);
		return (false);
	}
}

bool
dbwrap_query_bind_uint64(dbwrap_query_t *query, unsigned long *val)
{
	MYSQL_BIND bval;
	bool res;

	if (query == NULL || val == NULL) {
		return (false);
	}

	memset(&bval, 0, sizeof(bval));
	switch (query->dq_ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		memset(&bval, 0, sizeof(bval));
		bval.buffer_type = MYSQL_TYPE_LONGLONG;
		bval.buffer = val;
		res = dbwrap_mysql_statement_bind(query->dq_qobj.dq_mysql,
		    &bval);
		if (res == false) {
			dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
			dbwrap_query_set_errorcode(query,
			    DBWRAP_ERROR_BACKEND);
		}
		return (res);
	case DBWRAP_SQLITE:
		res = dbwrap_sqlite_bind_int64(query->dq_qobj.dq_sqlite,
		    ++(query->dq_lastbind), *val);
		if (res == false) {
			dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
			dbwrap_query_set_errorcode(query,
			    DBWRAP_ERROR_BACKEND);
		}
		return (res);
	default:
		dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
		dbwrap_query_set_errorcode(query, DBWRAP_ERROR_WRAP);
		return (false);
	}
}

bool
dbwrap_query_bind_string(dbwrap_query_t *query, const char *val)
{
	MYSQL_BIND bval;
	bool res;

	if (query == NULL || val == NULL) {
		return (false);
	}

	switch (query->dq_ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		memset(&bval, 0, sizeof(bval));
		bval.buffer_type = MYSQL_TYPE_STRING;
		bval.buffer = (void *)val;
		bval.buffer_length = strlen(val);
		res = dbwrap_mysql_statement_bind(query->dq_qobj.dq_mysql,
		    &bval);
		if (res == false) {
			dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
			dbwrap_query_set_errorcode(query,
			    DBWRAP_ERROR_BACKEND);
		}
		return (res);
	case DBWRAP_SQLITE:
		res = dbwrap_sqlite_bind_string(query->dq_qobj.dq_sqlite,
		    ++(query->dq_lastbind), val);
		if (res == false) {
			dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
			dbwrap_query_set_errorcode(query,
			    DBWRAP_ERROR_BACKEND);
		}
		return (res);
	default:
		dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
		dbwrap_query_set_errorcode(query, DBWRAP_ERROR_WRAP);
		return (false);
	}
}

bool
dbwrap_query_bind_blob(dbwrap_query_t *query, void *val, size_t sz)
{
	MYSQL_BIND bval;
	bool res;

	if (query == NULL || val == NULL) {
		return (false);
	}

	memset(&bval, 0, sizeof(bval));
	switch (query->dq_ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		memset(&bval, 0, sizeof(bval));
		bval.buffer_type = MYSQL_TYPE_BLOB;
		bval.buffer = val;
		bval.buffer_length = sz;
		res = dbwrap_mysql_statement_bind(query->dq_qobj.dq_mysql,
		    &bval);
		if (res == false) {
			dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
			dbwrap_query_set_errorcode(query,
			    DBWRAP_ERROR_BACKEND);
		}
		return (res);
	case DBWRAP_SQLITE:
		res = dbwrap_sqlite_bind_blob(query->dq_qobj.dq_sqlite,
		    ++(query->dq_lastbind), val, sz);
		if (res == false) {
			dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
			dbwrap_query_set_errorcode(query,
			    DBWRAP_ERROR_BACKEND);
		}
		return (res);
	default:
		dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
		dbwrap_query_set_errorcode(query, DBWRAP_ERROR_WRAP);
		return (false);
	}
}

bool
dbwrap_query_exec(dbwrap_query_t *query)
{

	if (query == NULL) {
		fprintf(stderr, "[-] query cannot be null\n");
		return (false);
	}

	switch (query->dq_ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		return (dbwrap_mysql_statement_exec(query->dq_qobj.dq_mysql));
	case DBWRAP_SQLITE:
		return (dbwrap_sqlite_query_exec(query->dq_qobj.dq_sqlite));
	default:
		dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
		dbwrap_query_set_errorcode(query, DBWRAP_ERROR_WRAP);
		return (false);
	}
}

dbwrap_result_t *
dbwrap_query_result_fetch(dbwrap_query_t *query)
{
	dbwrap_mysql_statement_result_t *mresult;

	if (query == NULL) {
		return (NULL);
	}

	switch (query->dq_ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		mresult = dbwrap_mysql_fetch_results(query->dq_qobj.dq_mysql,
		    query->dq_flags);
		if (mresult == NULL) {
			return (NULL);
		}
		return (_dbwrap_convert_mysql_result(query, mresult));
	case DBWRAP_SQLITE:
		return (_dbrawp_convert_sqlite_result(query));
	default:
		break;
	}

	dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
	dbwrap_query_set_errorcode(query, DBWRAP_ERROR_WRAP);
	return (NULL);
}

dbwrap_row_t *
dbwrap_result_get_row(dbwrap_result_t *result, size_t reqid)
{
	dbwrap_row_t *row, *trow;
	size_t rowid;

	if (result == NULL) {
		return (NULL);
	}

	if (reqid > result->dr_nrows) {
		return (NULL);
	}

	rowid = 0;
	LIST_FOREACH_SAFE(row, &(result->dr_rows), dr_entry, trow) {
		if (rowid++ == reqid) {
			return (row);
		}
	}

	return (NULL);
}

dbwrap_column_t *
dbwrap_row_get_column(dbwrap_row_t *row, size_t reqid)
{
	dbwrap_column_t *column, *tcolumn;
	size_t colid;

	if (row == NULL) {
		return (NULL);
	}

	colid = 0;
	LIST_FOREACH_SAFE(column, &(row->dr_columns), dc_entry, tcolumn) {
		if (colid++ == reqid) {
			return (column);
		}
	}

	return (NULL);
}

int
dbwrap_column_to_int(dbwrap_column_t *column, int def)
{

	if (column == NULL) {
		return (def);
	}

	if (column->dc_type != DBWRAP_COLUMN_INT) {
		return (def);
	}

	return (*((int *)(column->dc_value)));
}

unsigned int
dbwrap_column_to_uint(dbwrap_column_t *column, unsigned int def)
{

	if (column == NULL) {
		return (def);
	}

	if (column->dc_type != DBWRAP_COLUMN_INT) {
		return (def);
	}

	if (column->dc_value == NULL) {
		return (def);
	}

	return (*((unsigned int *)(column->dc_value)));
}

long
dbwrap_column_to_long(dbwrap_column_t *column, long def)
{

	if (column == NULL) {
		return (def);
	}

	if (column->dc_type != DBWRAP_COLUMN_INT64) {
		return (def);
	}

	if (column->dc_value == NULL) {
		return (def);
	}

	return (*((long *)(column->dc_value)));
}

unsigned long
dbwrap_column_to_ulong(dbwrap_column_t *column, unsigned long def)
{

	if (column == NULL) {
		return (def);
	}

	if (column->dc_type != DBWRAP_COLUMN_INT64) {
		return (def);
	}

	if (column->dc_value == NULL) {
		return (def);
	}

	return (*((unsigned long *)(column->dc_value)));
}

char *
dbwrap_column_to_string(dbwrap_column_t *column)
{

	if (column == NULL) {
		return (NULL);
	}

	switch (column->dc_type) {
	case DBWRAP_COLUMN_TEXT:
	case DBWRAP_COLUMN_BLOB:
		return ((char *)(column->dc_value));
	default:
		return (NULL);
	}
}

void *
dbwrap_column_value(dbwrap_column_t *column)
{

	if (column == NULL) {
		return (NULL);
	}

	return (column->dc_value);
}

size_t
dbwrap_column_size(dbwrap_column_t *column)
{

	if (column == NULL) {
		return (0);
	}

	return (column->dc_size);
}

void
dbwrap_query_free(dbwrap_query_t **queryp)
{
	dbwrap_row_t *row, *trow;
	dbwrap_query_t *query;

	if (queryp == NULL || *queryp == NULL) {
		return;
	}

	query = *queryp;

	LIST_FOREACH_SAFE(row, &(query->dq_rows), dr_entry, trow) {
		LIST_REMOVE(row, dr_entry);
		dbwrap_row_free(&row);
	}

	switch (query->dq_ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		dbwrap_mysql_statement_free(&(query->dq_qobj.dq_mysql));
		break;
	case DBWRAP_SQLITE:
		dbwrap_sqlite_query_free(&(query->dq_qobj.dq_sqlite));
		break;
	default:
		break;
	}

	memset(query, 0, sizeof(*query));

	free(query);
	*queryp = NULL;
}

void
dbwrap_row_free(dbwrap_row_t **rowp)
{
	dbwrap_column_t *column, *tcolumn;
	dbwrap_row_t *row;

	if (rowp == NULL || *rowp == NULL) {
		return;
	}

	row = *rowp;

	LIST_FOREACH_SAFE(column, &(row->dr_columns), dc_entry, tcolumn) {
		LIST_REMOVE(column, dc_entry);
		dbwrap_column_free(&column);
	}

	memset(row, 0, sizeof(*row));

	free(row);
	*rowp = NULL;
}

void
dbwrap_column_free(dbwrap_column_t **columnp)
{
	dbwrap_column_t *column;
	uint64_t flags;

	if (columnp == NULL || *columnp == NULL) {
		return;
	}

	column = *columnp;

	flags = DBWRAP_QUERY_FLAG_ZERO_RESULTS;
	if (column->dc_row != NULL) {
		if (column->dc_row->dr_query != NULL) {
			flags = column->dc_row->dr_query->dq_flags;
		}
	}

	if (column->dc_value != NULL && column->dc_size > 0) {
		if ((flags & DBWRAP_QUERY_FLAG_ZERO_RESULTS) ==
		    DBWRAP_QUERY_FLAG_ZERO_RESULTS) {
			explicit_bzero(column->dc_value, column->dc_size);
		}
		free(column->dc_value);
	}

	memset(column, 0, sizeof(*column));

	free(column);
	*columnp = NULL;
}

void
dbwrap_result_free(dbwrap_result_t **resultp)
{
	dbwrap_row_t *row, *trow;
	dbwrap_result_t *result;

	if (resultp == NULL || *resultp == NULL) {
		return;
	}

	result = *resultp;

	LIST_FOREACH_SAFE(row, &(result->dr_rows), dr_entry, trow) {
		LIST_REMOVE(row, dr_entry);
		dbwrap_row_free(&row);
	}

	memset(result, 0, sizeof(*result));

	free(result);
	*resultp = NULL;
}

static dbwrap_result_t *
_dbwrap_convert_mysql_result(dbwrap_query_t *query,
    dbwrap_mysql_statement_result_t *mresult)
{
	dbwrap_mysql_row_t *mrow, *tmrow;
	dbwrap_column_t *column;
	dbwrap_result_t *result;
	dbwrap_row_t *row;
	size_t i;

	if (query == NULL || mresult == NULL) {
		return (NULL);
	}

	result = _dbwrap_result_new(query);
	if (result == NULL) {
		return (NULL);
	}

	LIST_FOREACH_SAFE(mrow, &(mresult->bmsr_rows), bmsb_entry, tmrow) {
		row = calloc(1, sizeof(*row));
		if (row == NULL) {
			goto end;
		}

		row->dr_query = query;
		LIST_INIT(&(row->dr_columns));

		for (i = 0; i < mresult->bmsr_ncols; i++) {
			column = calloc(1, sizeof(*column));
			if (column == NULL) {
				dbwrap_query_set_flag(query,
				    DBWRAP_QUERY_ERROR);
				dbwrap_query_set_errorcode(query,
				    DBWRAP_ERROR_ALLOC);
				dbwrap_row_free(&row);
				goto end;
			}

			column->dc_row = row;
			switch (mresult->bmsr_statement->bms_res->fields[i].type) {
			case MYSQL_TYPE_LONG:
				column->dc_type = DBWRAP_COLUMN_INT;
				column->dc_size = mrow->bmsb_colsizes[i];
				column->dc_value = calloc(1, column->dc_size);
				if (column->dc_value == NULL) {
					dbwrap_query_set_flag(query,
					    DBWRAP_QUERY_ERROR);
					dbwrap_query_set_errorcode(query,
					    DBWRAP_ERROR_ALLOC);
					dbwrap_row_free(&row);
					free(column);
					goto end;
				}
				memmove(column->dc_value,
				    mrow->bmsb_columns[i].buffer,
				    column->dc_size);
				break;
			case MYSQL_TYPE_LONGLONG:
				column->dc_type = DBWRAP_COLUMN_INT64;
				column->dc_size = mrow->bmsb_colsizes[i];
				column->dc_value = calloc(1, column->dc_size);
				if (column->dc_value == NULL) {
					dbwrap_query_set_flag(query,
					    DBWRAP_QUERY_ERROR);
					dbwrap_query_set_errorcode(query,
					    DBWRAP_ERROR_ALLOC);
					dbwrap_row_free(&row);
					free(column);
					goto end;
				}
				memmove(column->dc_value,
				    mrow->bmsb_columns[i].buffer,
				    column->dc_size);
				break;
			case MYSQL_TYPE_BLOB:
				column->dc_type = DBWRAP_COLUMN_BLOB;
				column->dc_size = mrow->bmsb_colsizes[i];
				column->dc_value = calloc(1, column->dc_size+1);
				if (column->dc_value == NULL) {
					dbwrap_query_set_flag(query,
					    DBWRAP_QUERY_ERROR);
					dbwrap_query_set_errorcode(query,
					    DBWRAP_ERROR_ALLOC);
					dbwrap_row_free(&row);
					free(column);
					goto end;
				}
				memmove(column->dc_value,
				    mrow->bmsb_columns[i].buffer,
				    column->dc_size);
				break;
			default:
				column->dc_type = DBWRAP_COLUMN_UNKNOWN;
				column->dc_size = mrow->bmsb_colsizes[i];
				column->dc_value = calloc(1, column->dc_size);
				if (column->dc_value == NULL) {
					dbwrap_query_set_flag(query,
					    DBWRAP_QUERY_ERROR);
					dbwrap_query_set_errorcode(query,
					    DBWRAP_ERROR_ALLOC);
					dbwrap_row_free(&row);
					free(column);
					goto end;
				}
				memmove(column->dc_value,
				    mrow->bmsb_columns[i].buffer,
				    column->dc_size);
				break;
			}

			if (i == 0) {
				LIST_INSERT_HEAD(&(row->dr_columns), column,
				    dc_entry);
			} else {
				LIST_INSERT_AFTER(row->dr_tail, column, dc_entry);
			}
			row->dr_tail = column;
		}

		result->dr_nrows++;
		LIST_INSERT_HEAD(&(result->dr_rows), row, dr_entry);
	}

end:
	dbwrap_mysql_statement_result_free(&mresult);
	return (result);
}

static dbwrap_result_t *
_dbrawp_convert_sqlite_result(dbwrap_query_t *query)
{
	dbwrap_sqlite_column_t *scolumn, *tscolumn;
	dbwrap_sqlite_row_t *srow, *tsrow;
	dbwrap_column_t *column;
	dbwrap_result_t *result;
	dbwrap_row_t *row;

	if (query == NULL) {
		return (NULL);
	}

	result = _dbwrap_result_new(query);
	if (result == NULL) {
		return (NULL);
	}

	LIST_FOREACH_SAFE(srow, &(query->dq_qobj.dq_sqlite->dsq_rows),
	    dsr_entry, tsrow) {
		row = calloc(1, sizeof(*row));
		if (row == NULL) {
			dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
			dbwrap_query_set_errorcode(query, DBWRAP_ERROR_ALLOC);
			goto end;
		}

		row->dr_query = query;
		LIST_INIT(&(row->dr_columns));

		LIST_FOREACH_SAFE(scolumn, &(srow->dsr_columns), dsc_entry,
		    tscolumn) {
			column = calloc(1, sizeof(*column));
			if (column == NULL) {
				dbwrap_query_set_flag(query,
				    DBWRAP_QUERY_ERROR);
				dbwrap_query_set_errorcode(query,
				    DBWRAP_ERROR_ALLOC);
				dbwrap_row_free(&row);
				goto end;
			}

			column->dc_row = row;
			switch (scolumn->dsc_type) {
			case DBWRAP_SQLITE_COLUMN_TEXT:
				column->dc_type = DBWRAP_COLUMN_TEXT;
				column->dc_size = scolumn->dsc_size;
				column->dc_value = calloc(1,
				    column->dc_size + 1);
				if (column->dc_value == NULL) {
					dbwrap_query_set_flag(query,
					    DBWRAP_QUERY_ERROR);
					dbwrap_query_set_errorcode(query,
					    DBWRAP_ERROR_ALLOC);
					dbwrap_row_free(&row);
					free(column);
					goto end;
				}
				memmove(column->dc_value, scolumn->dsc_value,
				    column->dc_size);
				break;
			case DBWRAP_SQLITE_COLUMN_INT:
				column->dc_type = DBWRAP_COLUMN_INT;
				column->dc_size = scolumn->dsc_size;
				column->dc_value = calloc(1,
				    column->dc_size);
				if (column->dc_value == NULL) {
					dbwrap_query_set_flag(query,
					    DBWRAP_QUERY_ERROR);
					dbwrap_query_set_errorcode(query,
					    DBWRAP_ERROR_ALLOC);
					dbwrap_row_free(&row);
					free(column);
					goto end;
				}
				memmove(column->dc_value, scolumn->dsc_value,
				    column->dc_size);
				break;
			case DBWRAP_SQLITE_COLUMN_INT64:
				column->dc_type = DBWRAP_COLUMN_INT64;
				column->dc_size = scolumn->dsc_size;
				column->dc_value = calloc(1,
				    column->dc_size);
				if (column->dc_value == NULL) {
					dbwrap_query_set_flag(query,
					    DBWRAP_QUERY_ERROR);
					dbwrap_query_set_errorcode(query,
					    DBWRAP_ERROR_ALLOC);
					dbwrap_row_free(&row);
					free(column);
					goto end;
				}
				memmove(column->dc_value, scolumn->dsc_value,
				    column->dc_size);
				break;
			case DBWRAP_SQLITE_COLUMN_BLOB:
				column->dc_type = DBWRAP_COLUMN_BLOB;
				column->dc_size = scolumn->dsc_size;
				column->dc_value = calloc(1,
				    column->dc_size);
				if (column->dc_value == NULL) {
					dbwrap_query_set_flag(query,
					    DBWRAP_QUERY_ERROR);
					dbwrap_query_set_errorcode(query,
					    DBWRAP_ERROR_ALLOC);
					dbwrap_row_free(&row);
					free(column);
					goto end;
				}
				memmove(column->dc_value, scolumn->dsc_value,
				    column->dc_size);
				break;
			default:
				dbwrap_row_free(&row);
				free(column);
				goto end;
			}

			if (row->dr_tail == NULL) {
				LIST_INSERT_HEAD(&(row->dr_columns), column,
				    dc_entry);
			} else {
				LIST_INSERT_AFTER(row->dr_tail, column,
				    dc_entry);
			}

			row->dr_tail = column;
		}

		result->dr_nrows++;
		LIST_INSERT_HEAD(&(result->dr_rows), row, dr_entry);
	}

end:
	return (result);
}

static dbwrap_result_t *
_dbwrap_result_new(dbwrap_query_t *query)
{
	dbwrap_result_t *result;

	if (query == NULL) {
		return (NULL);
	}

	result = calloc(1, sizeof(*result));
	if (result == NULL) {
		dbwrap_query_set_flag(query, DBWRAP_QUERY_ERROR);
		dbwrap_query_set_errorcode(query, DBWRAP_ERROR_ALLOC);
		return (NULL);
	}

	result->dr_query = query;
	LIST_INIT(&(result->dr_rows));

	return (result);
}
