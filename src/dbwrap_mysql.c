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

bool
dbwrap_mysql_init(void)
{

	if (mysql_library_init(0, NULL, NULL)) {
		return (false);
	}

	if (dbwrap_mysql_thread_init() == false) {
		return (false);
	}

	return (true);
}

bool
dbwrap_mysql_thread_init(void)
{

	return (mysql_thread_init());
}

bool
dbwrap_mysql_thread_cleanup(void)
{

	mysql_thread_end();
	return (true);
}

dbwrap_mysql_ctx_t *
dbwrap_mysql_ctx_init(dbwrap_ctx_t *dbctx, uint64_t flags, const char *host,
    const char *username, const char *password, const char *database,
    unsigned int port)
{
	dbwrap_mysql_ctx_t *ctx;

	if (host == NULL || username == NULL || password == NULL ||
	    database == NULL) {
		return (NULL);
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return (NULL);
	}

	ctx->bmc_host = strdup(host);
	if (ctx->bmc_host == NULL) {
		free(ctx);
		return (NULL);
	}

	ctx->bmc_database = strdup(database);
	if (ctx->bmc_database == NULL) {
		dbwrap_mysql_ctx_destroy(&ctx);
		return (NULL);
	}

	ctx->bmc_username = strdup(username);
	if (ctx->bmc_username == NULL) {
		dbwrap_mysql_ctx_destroy(&ctx);
		return (NULL);
	}

	ctx->bmc_password = strdup(password);
	if (ctx->bmc_password == NULL) {
		dbwrap_mysql_ctx_destroy(&ctx);
		return (NULL);
	}

	if (flags & DBWRAP_MYSQL_FLAG_THREAD_INIT) {
		if (dbwrap_mysql_thread_init() == false) {
			dbwrap_mysql_ctx_destroy(&ctx);
			return (NULL);
		}
	}

	if (pthread_mutex_init(&(ctx->bmc_mtx), NULL)) {
		dbwrap_mysql_ctx_destroy(&ctx);
		return (NULL);
	}

	ctx->bmc_internal_flags |=
	    DBWRAP_MYSQL_CTX_INTERNAL_FLAG_MTX_INITTED;

	ctx->bmc_mysql = mysql_init(NULL);
	if (ctx->bmc_mysql == NULL) {
		dbwrap_mysql_ctx_destroy(&ctx);
		return (NULL);
	}

	ctx->bmc_port = port;
	ctx->bmc_flags = flags;
	ctx->bmc_version = DBWRAP_MYSQL_VERSION;
	ctx->bmc_dbctx = dbctx;

	return (ctx);
}

void
dbwrap_mysql_ctx_destroy(dbwrap_mysql_ctx_t **ctxp)
{
	dbwrap_mysql_ctx_t *ctx;

	if (ctxp == NULL || *ctxp == NULL) {
		return;
	}

	ctx = *ctxp;

	if (ctx->bmc_internal_flags &
	    DBWRAP_MYSQL_CTX_INTERNAL_FLAG_MTX_INITTED) {
		pthread_mutex_destroy(&(ctx->bmc_mtx));
	}

	if (ctx->bmc_mysql != NULL) {
		mysql_close(ctx->bmc_mysql);
	}

	if (ctx->bmc_username != NULL) {
		explicit_bzero(ctx->bmc_username, strlen(ctx->bmc_username));
		free(ctx->bmc_username);
	}

	if (ctx->bmc_password != NULL) {
		explicit_bzero(ctx->bmc_password, strlen(ctx->bmc_password));
		free(ctx->bmc_password);
	}

	explicit_bzero(ctx, sizeof(*ctx));
	free(ctx->bmc_database);
	free(ctx);

	*ctxp = NULL;
}

bool
dbwrap_mysql_ctx_lock(dbwrap_mysql_ctx_t *ctx)
{

	if (ctx == NULL) {
		return (false);
	}

	return (pthread_mutex_lock(&(ctx->bmc_mtx)) == 0);
}

void
dbwrap_mysql_ctx_unlock(dbwrap_mysql_ctx_t *ctx)
{

	if (ctx == NULL) {
		return;
	}

	pthread_mutex_unlock(&(ctx->bmc_mtx));
}

bool
dbwrap_mysql_connect(dbwrap_mysql_ctx_t *ctx)
{
	unsigned int flags;
	bool set;

	if (ctx == NULL || ctx->bmc_mysql == NULL) {
		fprintf(stderr, "[-] ctx: %p\n", ctx);
		if (ctx != NULL) {
			fprintf(stderr, "    bmc_mysql: %p\n", ctx->bmc_mysql);
		}
		return (false);
	}

	set = true;
	if (mysql_options(ctx->bmc_mysql, MYSQL_OPT_RECONNECT, &set)) {
		fprintf(stderr, "[-] mysql_options(MYSQL_OPT_RECONNECT) failed\n");
		return (false);
	}

	set = false;
	if (mysql_options(ctx->bmc_mysql, MYSQL_REPORT_DATA_TRUNCATION, &set)) {
		fprintf(stderr, "[-] mysql_options(MYSQL_REPORT_DATA_TRUNCATION,) failed\n");
		return (false);
	}

	flags = 0;
	flags |= CLIENT_REMEMBER_OPTIONS;

	if (ctx->bmc_flags & DBWRAP_MYSQL_FLAG_MULTI_STATEMENTS) {
		flags |= CLIENT_MULTI_STATEMENTS;
	}

	if (ctx->bmc_flags & DBWRAP_MYSQL_FLAG_USE_DNS_SRV) {
		if (!mysql_real_connect_dns_srv(ctx->bmc_mysql, ctx->bmc_host,
		    ctx->bmc_username, ctx->bmc_password, ctx->bmc_database,
		    flags)) {
			return (false);
		}
	} else {
		if (!mysql_real_connect(ctx->bmc_mysql, ctx->bmc_host,
		    ctx->bmc_username, ctx->bmc_password, ctx->bmc_database,
		    ctx->bmc_port, NULL, flags)) {
			fprintf(stderr, "[-] mysql_real_connect failed\n");
			return (false);
		}
	}

	return (true);
}

dbwrap_mysql_statement_t *
dbwrap_mysql_statement_init(dbwrap_query_t *dbquery, dbwrap_mysql_ctx_t *ctx,
    const char *query, uint64_t flags)
{
	dbwrap_mysql_statement_t *stmt;

	if (ctx == NULL || query == NULL) {
		return (NULL);
	}

	stmt = calloc(1, sizeof(*stmt));
	if (stmt == NULL) {
		return (NULL);
	}

	stmt->bms_query = strdup(query);
	if (stmt->bms_query == NULL) {
		free(stmt);
		return (NULL);
	}

	stmt->bms_statement = mysql_stmt_init(ctx->bmc_mysql);
	if (stmt->bms_statement == NULL) {
		free(stmt->bms_query);
		free(stmt);
		return (NULL);
	}

	stmt->bms_ctx = ctx;
	stmt->bms_flags = flags;
	stmt->bms_dbquery = dbquery;
	LIST_INIT(&(stmt->bms_binds));

	return (stmt);
}

void
dbwrap_mysql_statement_destroy(dbwrap_mysql_statement_t **stmtp)
{
	dbwrap_mysql_statement_bind_t *msbind, *tmsbind;
	dbwrap_mysql_statement_t *stmt;

	if (stmtp == NULL || *stmtp == NULL) {
		return;
	}

	stmt = *stmtp;
	LIST_FOREACH_SAFE(msbind, &(stmt->bms_binds), bmsb_entry, tmsbind) {
		LIST_REMOVE(msbind, bmsb_entry);
		/*
		 * We want to explicitly zero the bound data in case
		 * there is sensitive information contained within it.
		 * For example, if we are binding a password.
		 */
		explicit_bzero(msbind, sizeof(*msbind));
		free(msbind);
	}

	if (stmt->bms_statement != NULL) {
		mysql_stmt_close(stmt->bms_statement);
	}

	free(stmt);

	*stmtp = NULL;
}

bool
dbwrap_mysql_statement_bind(dbwrap_mysql_statement_t *stmt, MYSQL_BIND *val)
{
	dbwrap_mysql_statement_bind_t *bval;

	if (stmt == NULL || val == NULL) {
		return (false);
	}

	bval = calloc(1, sizeof(*bval));
	if (bval == NULL) {
		dbwrap_query_set_errorcode(stmt->bms_dbquery,
		    DBWRAP_ERROR_ALLOC);
		return (false);
	}

	memmove(&(bval->bmsb_bind), val, sizeof(*val));

	/*
	 * Normally, we would use LIST_INSERT_HEAD, but that would
	 * reverse the desired order of the bound parameters when it's
	 * time to pass them to MySQL itself.
	 */
	if (stmt->bms_last != NULL) {
		LIST_INSERT_AFTER(stmt->bms_last, bval, bmsb_entry);
	} else {
		LIST_INSERT_HEAD(&(stmt->bms_binds), bval, bmsb_entry);
	}
	stmt->bms_last = bval;
	stmt->bms_nbinds++;

	return (true);
}

bool
dbwrap_mysql_statement_exec(dbwrap_mysql_statement_t *stmt)
{
	dbwrap_mysql_statement_bind_t *sbind, *tsbind;
	MYSQL_BIND *msbind;
	bool locked, res;
	size_t i;

	if (stmt == NULL) {
		return (false);
	}

	res = true;
	msbind = NULL;
	locked = false;

	if (mysql_stmt_prepare(stmt->bms_statement, stmt->bms_query,
	    strlen(stmt->bms_query))) {
		dbwrap_query_set_errorcode(stmt->bms_dbquery,
		    DBWRAP_ERROR_BACKEND);
		res = false;
		goto end;
	}

	if (mysql_stmt_param_count(stmt->bms_statement) != stmt->bms_nbinds) {
		dbwrap_query_set_errorcode(stmt->bms_dbquery,
		    DBWRAP_ERROR_BACKEND);
		res = false;
		goto end;
	}

	if (stmt->bms_nbinds > 0) {
		if (stmt->bms_nbinds * sizeof(*msbind) < sizeof(*msbind)) {
			return (false);
		}
		msbind = calloc(stmt->bms_nbinds, sizeof(*msbind));
		if (msbind == NULL) {
			return (false);
		}

		i = 0;
		LIST_FOREACH_SAFE(sbind, &(stmt->bms_binds), bmsb_entry,
		    tsbind) {
			memmove(msbind + i, &(sbind->bmsb_bind),
			    sizeof(*msbind));
			i++;
		}
	}

	if (msbind && mysql_stmt_bind_param(stmt->bms_statement, msbind)) {
		dbwrap_query_set_errorcode(stmt->bms_dbquery,
		    DBWRAP_ERROR_BACKEND);
		res = false;
		goto end;
	}

	if (!dbwrap_mysql_ctx_lock(stmt->bms_ctx)) {
		res = false;
		goto end;
	}

	locked = true;

	if (mysql_stmt_execute(stmt->bms_statement)) {
		dbwrap_query_set_errorcode(stmt->bms_dbquery,
		    DBWRAP_ERROR_BACKEND);
		res = false;
		goto end;
	}

	if (mysql_stmt_store_result(stmt->bms_statement)) {
		dbwrap_query_set_errorcode(stmt->bms_dbquery,
		    DBWRAP_ERROR_BACKEND);
		res = false;
		goto end;
	}

	stmt->bms_res = mysql_stmt_result_metadata(stmt->bms_statement);

end:
	if (locked) {
		dbwrap_mysql_ctx_unlock(stmt->bms_ctx);
	}
	free(msbind);
	return (res);
}

void
dbwrap_mysql_statement_free(dbwrap_mysql_statement_t **stmtp)
{
	dbwrap_mysql_statement_bind_t *msbind, *tmsbind;
	dbwrap_mysql_statement_t *stmt;

	if (stmtp == NULL || *stmtp == NULL) {
		return;
	}

	stmt = *stmtp;

	LIST_FOREACH_SAFE(msbind, &(stmt->bms_binds), bmsb_entry, tmsbind) {
		LIST_REMOVE(msbind, bmsb_entry);
		free(msbind);
	}

	if (stmt->bms_statement != NULL) {
		mysql_stmt_free_result(stmt->bms_statement);
		mysql_stmt_close(stmt->bms_statement);
	}

	free(stmt);
	*stmtp = NULL;
}

dbwrap_mysql_statement_result_t *
dbwrap_mysql_fetch_results(dbwrap_mysql_statement_t *stmt)
{
	dbwrap_mysql_statement_result_t *res;
	dbwrap_mysql_row_t *row;
	unsigned long sz;
	int status;
	size_t i, j;

	if (stmt == NULL) {
		return (NULL);
	}

	res = calloc(1, sizeof(*res));
	if (res == NULL) {
		return (NULL);
	}

	res->bmsr_statement = stmt;
	LIST_INIT(&(res->bmsr_rows));

	if (stmt->bms_res == NULL) {
		/*
		 * bms_res being NULL means that no rows were
		 * returned.
		 */
		return (res);
	}

	res->bmsr_ncols = mysql_num_fields(stmt->bms_res);

	if (res->bmsr_ncols == 0) {
		return (res);
	}

	for (j = 0; ; j++) {
		row = calloc(1, sizeof(*row));
		if (row == NULL) {
			res->bmsr_ncols = 0;
			return (res);
		}

		if (res->bmsr_ncols * sizeof(*(row->bmsb_columns)) <
		    sizeof(*(row->bmsb_columns))) {
			free(row);
			res->bmsr_ncols = 0;
			return (res);
		}

		row->bmsb_colsizes = calloc(res->bmsr_ncols,
		    sizeof(*(row->bmsb_colsizes)));
		if (row->bmsb_colsizes == NULL) {
			free(row);
			res->bmsr_ncols = 0;
			return (res);
		}

		row->bmsb_columns = calloc(res->bmsr_ncols,
		    sizeof(*(row->bmsb_columns)));
		if (row->bmsb_columns == NULL) {
			free(row->bmsb_colsizes);
			free(row);
			res->bmsr_ncols = 0;
			return (res);
		}

		for (i = 0; i < res->bmsr_ncols; i++) {
			row->bmsb_columns[i].length = row->bmsb_colsizes + i;
		}

		if (!mysql_stmt_bind_result(stmt->bms_statement,
		    row->bmsb_columns) && mysql_stmt_errno(stmt->bms_statement)) {
			dbwrap_query_set_errorcode(stmt->bms_dbquery,
			    DBWRAP_ERROR_BACKEND);
			free(row->bmsb_colsizes);
			free(row);
			res->bmsr_ncols = 0;
			return (res);
		}

		status = mysql_stmt_fetch(stmt->bms_statement);
		if (status == 1) {
			free(row->bmsb_colsizes);
			free(row);
			res->bmsr_ncols = 0;
			return (res);
		}

		if (status == MYSQL_NO_DATA) {
			free(row->bmsb_colsizes);
			free(row);
			res->bmsr_ncols = 0;
			return (res);
		}

		if (status == MYSQL_DATA_TRUNCATED) {
			free(row->bmsb_colsizes);
			free(row);
			res->bmsr_ncols = 0;
			break;
		}

		for (i = 0; i < res->bmsr_ncols; i++) {
			row->bmsb_columns[i].buffer = calloc(1,
			    row->bmsb_colsizes[i]+1);
			if (row->bmsb_columns[i].buffer == NULL) {
				break;
			}

			row->bmsb_columns[i].buffer_length = row->bmsb_colsizes[i];
			row->bmsb_columns[i].buffer_type = stmt->bms_res->fields[i].type;
			if (mysql_stmt_fetch_column(stmt->bms_statement,
			    row->bmsb_columns + i, i, 0)) {
				free(row->bmsb_columns[i].buffer);
				break;
			}
		}

		if (i < res->bmsr_ncols) {
			free(row->bmsb_colsizes);
			free(row);
			res->bmsr_ncols = 0;
			return (res);
		}

		LIST_INSERT_HEAD(&(res->bmsr_rows), row, bmsb_entry);
	}

	return (res);
}

void
dbwrap_mysql_statement_result_free(
    dbwrap_mysql_statement_result_t **resp)
{
	dbwrap_mysql_statement_result_t *res;
	dbwrap_mysql_row_t *row, *trow;
	size_t i;

	if (resp == NULL || *resp == NULL) {
		return;
	}

	res = *resp;

	LIST_FOREACH_SAFE(row, &(res->bmsr_rows), bmsb_entry, trow) {
		LIST_REMOVE(row, bmsb_entry);
		free(row->bmsb_colsizes);
		for (i = 0; i < res->bmsr_ncols; i++) {
			explicit_bzero(row->bmsb_columns[i].buffer,
			    row->bmsb_columns[i].buffer_length);
			free(row->bmsb_columns[i].buffer);
		}
		free(row->bmsb_columns);
		free(row);
	}

	free(res);
	*resp = NULL;
}
