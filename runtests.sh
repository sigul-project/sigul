#!/usr/bin/bash -x
docker build -t sigul_tests tests || (echo "Failed to build"; exit)
docker run -it -v `pwd`:/testcode:z --tmpfs /testcode/testsuite.dir sigul_tests
