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

#include "dbwrap_sqlite.h"

dbwrap_sqlite_ctx_t *
dbwrap_sqlite_ctx_new(const char *path, uint64_t flags)
{
	dbwrap_sqlite_ctx_t *ctx;

	if (path == NULL) {
		return (NULL);
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return (NULL);
	}

	ctx->dsc_path = strdup(path);
	if (ctx->dsc_path == NULL) {
		free(ctx);
		return (NULL);
	}

	ctx->dsc_flags = flags;
	ctx->dsc_version = DBWRAP_SQLITE_VERSION;
	if (pthread_mutex_init(&(ctx->dsc_mtx), NULL)) {
		free(ctx->dsc_path);
		free(ctx);
		return (NULL);
	}

	if (sqlite3_open(ctx->dsc_path, &(ctx->dsc_ctx)) != SQLITE_OK) {
		free(ctx->dsc_path);
		free(ctx);
		return (NULL);
	}

	ctx->dsc_internal_flags |= DBWRAP_SQLITE_INTERNAL_INIT;

	return (ctx);
}

void
dbwrap_sqlite_ctx_free(dbwrap_sqlite_ctx_t **ctxp)
{
	dbwrap_sqlite_ctx_t *ctx;

	if (ctxp == NULL || *ctxp == NULL) {
		return;
	}

	if (ctx->dsc_internal_flags & DBWRAP_SQLITE_INTERNAL_INIT) {
		pthread_mutex_destroy(&(ctx->dsc_mtx));
	}

	ctx = *ctxp;
	if (ctx->dsc_ctx != NULL) {
		sqlite3_close(ctx->dsc_ctx);
	}

	free(ctx->dsc_path);
	free(ctx);

	*ctxp = NULL;
}

dbwrap_sqlite_query_t *
dbwrap_sqlite_query_new(dbwrap_sqlite_ctx_t *ctx, const char *querystr,
    uint64_t flags)
{
	dbwrap_sqlite_query_t *query;

	if (ctx == NULL || querystr == NULL) {
		return (NULL);
	}

	query = calloc(1, sizeof(*query));
	if (query == NULL) {
		return (NULL);
	}

	query->dsq_query = strdup(querystr);
	if (query->dsq_query == NULL) {
		free(query);
		return (NULL);
	}

	LIST_INIT(&(query->dsq_rows));
	query->dsq_ctx = ctx;
	query->dsq_flags = flags;

	if (sqlite3_prepare_v2(ctx->dsc_ctx, query->dsq_query, -1,
	    &(query->dsq_stmt), NULL) != SQLITE_OK) {
		dbwrap_sqlite_query_free(&query);
		return (NULL);
	}

	return (query);
}

bool
dbwrap_sqlite_query_exec(dbwrap_sqlite_query_t *query)
{
	bool breakout, ret;
	int res;

	if (query == NULL) {
		return (false);
	}

	ret = true;

	while (true) {
		breakout = false;
		res = sqlite3_step(query->dsq_stmt);
		switch (res) {
		case SQLITE_DONE:
			goto end;
		case SQLITE_ROW:
			if (!dbwrap_sqlite_add_row(query)) {
				ret = false;
				goto end;
			}
			break;
		default:
			ret = false;
			goto end;
		}
	}

end:
	return (ret);
}

bool
dbwrap_sqlite_add_row(dbwrap_sqlite_query_t *query)
{
	dbwrap_sqlite_column_t *column;
	const unsigned char *strval;
	dbwrap_sqlite_row_t *row;
	size_t i, sz;
	bool ret;
	long ival;

	if (query == NULL) {
		return (false);
	}

	ret = true;

	if (query->dsq_ncolumns == 0) {
		query->dsq_ncolumns = sqlite3_column_count(query->dsq_stmt);
		if (query->dsq_ncolumns == 0) {
			return (false);
		}
	}

	row = calloc(1, sizeof(*row));
	if (row == NULL) {
		return (false);
	}

	for (i = 0; i < query->dsq_ncolumns; i++) {
		column = calloc(1, sizeof(*column));
		if (column == NULL) {
			ret = false;
			goto end;
		}

		switch (sqlite3_column_type(query->dsq_stmt, i)) {
		case SQLITE_INTEGER:
			column->dsc_size = sizeof(ival);
			column->dsc_value = calloc(1, sizeof(ival));
			if (column->dsc_value == NULL) {
				free(column);
				ret = false;
				goto end;
			}
			column->dsc_type = DBWRAP_SQLITE_COLUMN_INT64;
			ival = sqlite3_column_int64(query->dsq_stmt, i);
			memmove(column->dsc_value, &ival, sizeof(ival));
			break;
		case SQLITE_TEXT:
			column->dsc_size = sqlite3_column_bytes(query->dsq_stmt, i);
			if (column->dsc_size == 0) {
				ret = false;
				goto end;
			}
			/* Ensure NUL termination by adding one to the size */
			column->dsc_value = calloc(1, column->dsc_size + 1);
			if (column->dsc_value == NULL) {
				free(column);
				ret = false;
				goto end;
			}
			strval = sqlite3_column_text(query->dsq_stmt, i);
			if (strval == NULL) {
				free(column);
				ret = false;
				goto end;
			}
			memmove(column->dsc_value, strval, column->dsc_size);
			column->dsc_type = DBWRAP_SQLITE_COLUMN_TEXT;
			break;
		case SQLITE_BLOB:
			column->dsc_size = sqlite3_column_bytes(query->dsq_stmt, i);
			if (column->dsc_size == 0) {
				ret = false;
				goto end;
			}
			column->dsc_value = calloc(1, column->dsc_size);
			if (column->dsc_value == NULL) {
				free(column);
				ret = false;
				goto end;
			}
			strval = sqlite3_column_text(query->dsq_stmt, i);
			if (strval == NULL) {
				free(column);
				ret = false;
				goto end;
			}
			memmove(column->dsc_value, strval, column->dsc_size);
			column->dsc_type = DBWRAP_SQLITE_COLUMN_BLOB;
			break;
		default:
			free(column);
			ret = false;
			goto end;
		}

		if (i == 0) {
			LIST_INSERT_HEAD(&(row->dsr_columns), column, dsc_entry);
		} else {
			LIST_INSERT_AFTER(row->dsr_tail, column, dsc_entry);
		}

		row->dsr_tail = column;
	}

end:
	if (ret == false) {
		dbwrap_sqlite_row_free(&row);
	} else {
		LIST_INSERT_HEAD(&(query->dsq_rows), row, dsr_entry);
	}
	return (ret);
}

void
dbwrap_sqlite_query_free(dbwrap_sqlite_query_t **queryp)
{
	dbwrap_sqlite_row_t *row, *trow;
	dbwrap_sqlite_query_t *query;

	if (queryp == NULL || *queryp == NULL) {
		return;
	}

	query = *queryp;
	if (query->dsq_query != NULL) {
		explicit_bzero(query->dsq_query, strlen(query->dsq_query));
		free(query->dsq_query);
	}

	if (query->dsq_stmt != NULL) {
		sqlite3_finalize(query->dsq_stmt);
	}

	LIST_FOREACH_SAFE(row, &(query->dsq_rows), dsr_entry, trow) {
		LIST_REMOVE(row, dsr_entry);
		dbwrap_sqlite_row_free(&row);
	}

	free(query);

	*queryp = NULL;
}

void
dbwrap_sqlite_row_free(dbwrap_sqlite_row_t **rowp)
{
	dbwrap_sqlite_column_t *col, *tcol;
	dbwrap_sqlite_row_t *row;

	if (rowp == NULL || *rowp == NULL) {
		return;
	}

	row = *rowp;

	LIST_FOREACH_SAFE(col, &(row->dsr_columns), dsc_entry, tcol) {
		LIST_REMOVE(col, dsc_entry);
		dbwrap_sqlite_column_free(&col);
	}

	free(row);
	*rowp = NULL;
}

void
dbwrap_sqlite_column_free(dbwrap_sqlite_column_t **colp)
{
	dbwrap_sqlite_column_t *col;

	if (colp == NULL || *colp == NULL) {
		return;
	}

	col = *colp;

	if (col->dsc_value != NULL) {
		explicit_bzero(col->dsc_value, col->dsc_size);
		free(col->dsc_value);
	}

	free(col);
	*colp = NULL;
}

bool
dbwrap_sqlite_bind_int(dbwrap_sqlite_query_t *query, int paramno, int val)
{

	if (query == NULL) {
		return (false);
	}

	return (sqlite3_bind_int(query->dsq_stmt, paramno, val) == SQLITE_OK);
}

bool
dbwrap_sqlite_bind_int64(dbwrap_sqlite_query_t *query, int paramno, long val)
{

	if (query == NULL) {
		return (false);
	}

	return (sqlite3_bind_int64(query->dsq_stmt, paramno, val) ==
	    SQLITE_OK);
}

bool
dbwrap_sqlite_bind_string(dbwrap_sqlite_query_t *query, int paramno,
    const char *val)
{

	if (query == NULL) {
		return (false);
	}

	return (sqlite3_bind_text(query->dsq_stmt, paramno, val, -1,
	    SQLITE_TRANSIENT) == SQLITE_OK);
}

bool
dbwrap_sqlite_bind_blob(dbwrap_sqlite_query_t *query, int paramno, void *val,
    size_t size)
{

	if (query == NULL) {
		return (false);
	}

	return (sqlite3_bind_blob(query->dsq_stmt, paramno, val, (int)size,
	    NULL) == SQLITE_OK);
}
