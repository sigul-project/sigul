#!/usr/bin/bash
autoreconf -vi
./configure
rm -f tests/testsuite
make
make check
