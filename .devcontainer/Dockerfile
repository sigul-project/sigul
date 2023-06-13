FROM fedora:latest

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=1000

RUN groupadd --gid $USER_GID $USERNAME \
        && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
        && dnf install -y sudo \
        && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
        && chmod 0440 /etc/sudoers.d/$USERNAME

RUN dnf install -y \
        python3-six python3-nss python3-requests python3-koji python3-rpm python3-cryptography \
        python3-gpg python3-sqlalchemy python3-pycodestyle \
        gnupg2 ostree-devel nss-tools rpm-build rpm-sign \
        cargo autoconf automake make bandit openssl ostree \
        skopeo psmisc

USER $USERNAME
