# libdbwrap

## Introduction

`libdbwrap` is a secure and unified database abstraction library. The
initial goal is to support MySQL and SQLite3. Consumers of the API
should not have to care what the underlying backend is once the
backend is selected at `dbwrap` context creation time.

Note that this project is under heavy and active development. Neither
the API nor ABI should be considered stable at the moment. The
unification API development is in progress, though not supported at
the moment.

License: 2-Clause BSD License

### Requirements

* `libmysqlclient` from MySQL 8.0
* `libsqlite3`

### Portability

The code itself should be portable across Linux and the BSDs, assuming
the above requirements are met. The Makefile, though, is written in
BSD make.

All development is done in a HardenedBSD 13-STABLE environment.
Support for other operating systems is left as an exercise for the
wider community.

## Supported Database Types

Only a subset of database data types are supported at the moment. Support for
more data types will be added in the future.

For MySQL:

1. `MYSQL_TYPE_LONG` -> `DBWRAP_COLUMN_INT`
1. `MYSQL_TYPE_BLOB` -> `DBWRAP_COLUMN_BLOB`

For SQLite3:

1. `SQLITE_INTEGER` -> `DBWRAP_COLUMN_INT`
1. `SQLITE_TEXT` -> `DBWRAP_COLUMN_TEXT`
1. `SQLITE_BLOB` -> `DBWRAP_COLUMN_BLOB`

String/textual types (`DBWRAP_COLUMN_TEXT`) are guaranteed to be NUL
terminated.
