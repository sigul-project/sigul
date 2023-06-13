#!/usr/bin/bash -x
if [ "$RUN_TESTS_DIRECTLY" == "true" ];
then
    echo "Running directly"
    exec ./tests/incontainer_run.sh
else
    docker build -t sigul_tests tests || (echo "Failed to build"; exit)
    exec docker run -it -v `pwd`:/testcode:z --tmpfs /testcode/testsuite.dir sigul_tests
fi
