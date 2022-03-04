# libdbwrap

## Introduction

`libdbwrap` is a database abstraction library. The initial goal is to
support MySQL and SQLite3.

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
