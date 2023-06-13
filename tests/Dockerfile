FROM fedora:latest

RUN mkdir /testcode
RUN dnf install -y \
        python3-six python3-nss python3-requests python3-koji python3-rpm python3-cryptography \
        python3-gpg python3-sqlalchemy python3-pycodestyle \
        gnupg2 ostree-devel nss-tools rpm-build rpm-sign \
        cargo autoconf automake make bandit openssl ostree \
        skopeo

VOLUME /testcode/testsuite.dir
WORKDIR /testcode
COPY incontainer_run.sh /usr/local/bin/runtests.sh

CMD [ "/usr/local/bin/runtests.sh" ]
