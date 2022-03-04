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

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return (ctx);
	}

	ctx->dc_flags = flags;
	ctx->dc_dbtype = dbtype;
	ctx->dc_version = DBWRAP_VERSION;

	return (ctx);
}

bool
dbwrap_ctx_sqlite_configure(dbwrap_ctx_t *ctx, const char *path,
    uint64_t flags)
{

	if (ctx == NULL || ctx->dc_dbtype != DBWRAP_SQLITE) {
		return (false);
	}

	ctx->dc_dbctx.dc_sqlite = dbwrap_sqlite_ctx_new(path, flags);

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

	ctx->dc_dbctx.dc_mysql = dbwrap_mysql_ctx_init(flags, host, username,
	    password, database, port);

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
		    ctx->dc_dbctx.dc_mysql, querystr, flags);
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

bool
dbwrap_query_bind_int(dbwrap_query_t *query, int *val)
{
	MYSQL_BIND bval;

	if (query == NULL) {
		return (false);
	}

	memset(&bval, 0, sizeof(bval));
	switch (query->dq_ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		memset(&bval, 0, sizeof(bval));
		bval.buffer_type = MYSQL_TYPE_LONG;
		bval.buffer = val;
		return (dbwrap_mysql_statement_bind(query->dq_qobj.dq_mysql,
		    &bval));
	case DBWRAP_SQLITE:
		return (dbwrap_sqlite_bind_int(query->dq_qobj.dq_sqlite,
		    ++(query->dq_lastbind), *val));
		break;
	default:
		return (false);
	}
}

bool
dbwrap_query_bind_string(dbwrap_query_t *query, const char *val)
{
	MYSQL_BIND bval;

	if (query == NULL) {
		return (false);
	}

	memset(&bval, 0, sizeof(bval));
	switch (query->dq_ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		memset(&bval, 0, sizeof(bval));
		bval.buffer_type = MYSQL_TYPE_STRING;
		bval.buffer = (void *)val;
		bval.buffer_length = strlen(val);
		return (dbwrap_mysql_statement_bind(query->dq_qobj.dq_mysql,
		    &bval));
	case DBWRAP_SQLITE:
		return (dbwrap_sqlite_bind_string(query->dq_qobj.dq_sqlite,
		    ++(query->dq_lastbind), val));
		break;
	default:
		return (false);
	}
}

bool
dbwrap_query_bind_blob(dbwrap_query_t *query, void *val, size_t sz)
{
	MYSQL_BIND bval;

	if (query == NULL) {
		return (false);
	}

	memset(&bval, 0, sizeof(bval));
	switch (query->dq_ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		memset(&bval, 0, sizeof(bval));
		bval.buffer_type = MYSQL_TYPE_BLOB;
		bval.buffer = val;
		bval.buffer_length = sz;
		return (dbwrap_mysql_statement_bind(query->dq_qobj.dq_mysql,
		    &bval));
	case DBWRAP_SQLITE:
		return (dbwrap_sqlite_bind_blob(query->dq_qobj.dq_sqlite,
		    ++(query->dq_lastbind), val, sz));
		break;
	default:
		return (false);
	}
}

bool
dbwrap_query_exec(dbwrap_query_t *query)
{

	if (query == NULL) {
		return (false);
	}

	switch (query->dq_ctx->dc_dbtype) {
	case DBWRAP_MYSQL:
		return (dbwrap_mysql_statement_exec(query->dq_qobj.dq_mysql));
	case DBWRAP_SQLITE:
		return (dbwrap_sqlite_query_exec(query->dq_qobj.dq_sqlite));
	default:
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
		mresult = dbwrap_mysql_fetch_results(query->dq_qobj.dq_mysql);
		if (mresult == NULL) {
			return (NULL);
		}
		return (_dbwrap_convert_mysql_result(query, mresult));
	case DBWRAP_SQLITE:
		return (_dbrawp_convert_sqlite_result(query));
	default:
		break;
	}

	return (NULL);
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

		LIST_INIT(&(row->dr_columns));

		for (i = 0; i < mresult->bmsr_ncols; i++) {
			column = calloc(1, sizeof(*column));
			if (column == NULL) {
				goto end;
			}

			switch (mresult->bmsr_statement->bms_res->fields[i].type) {
			case MYSQL_TYPE_LONG:
				column->dc_type = DBWRAP_COLUMN_INT;
				column->dc_size = mrow->bmsb_colsizes[i];
				column->dc_value = calloc(1, column->dc_size);
				if (column->dc_value == NULL) {
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

		LIST_INSERT_HEAD(&(result->dr_rows), row, dr_entry);
	}

end:
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
			goto end;
		}

		LIST_INIT(&(row->dr_columns));

		LIST_FOREACH_SAFE(scolumn, &(srow->dsr_columns), dsc_entry,
		    tscolumn) {
			column = calloc(1, sizeof(*column));
			if (column == NULL) {
				/* TODO: Clean up entire row */
				goto end;
			}

			switch (scolumn->dsc_type) {
			case DBWRAP_SQLITE_COLUMN_TEXT:
				column->dc_type = DBWRAP_COLUMN_TEXT;
				column->dc_size = scolumn->dsc_size;
				column->dc_value = calloc(1,
				    column->dc_size + 1);
				if (column->dc_value == NULL) {
					/* TODO: Clean up entire row */
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
					/* TODO: Clean up entire row */
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
					/* TODO: Clean up entire row */
					goto end;
				}
				memmove(column->dc_value, scolumn->dsc_value,
				    column->dc_size);
				break;
			default:
				/* TODO: Clean up entire row */
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
		return (NULL);
	}

	result->dr_query = query;
	LIST_INIT(&(result->dr_rows));

	return (result);
}
