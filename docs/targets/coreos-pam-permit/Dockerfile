# Vulnerable target for the vuln-coreos-pam-permit check (CVE-2016-4455).
#
# CoreOS Linux Alpha 1045.0.0 and 1047.0.0 shipped a PAM stack where
# pam_sss and pam_unix were both "sufficient" and the stack ended with
# "auth optional pam_permit.so". When neither module succeeded, PAM fell
# through to pam_permit and the login was allowed, so any password opened
# a session for any user, including the password-less core and operator
# accounts.
#
# Those releases ran OpenSSH 7.2p2 from Gentoo with UsePAM yes,
# PasswordAuthentication no and ChallengeResponseAuthentication yes, so
# the bypass was reached over keyboard-interactive. Upstream sshd announces
# SSH-2.0-OpenSSH_7.2 (no portable suffix, no addendum), which is the
# banner the check gates on. Debian and Ubuntu packages always add the
# "p2" suffix, so OpenSSH 7.2p2 is built from the upstream tarball here,
# with PAM, on Ubuntu 16.04 for its OpenSSL 1.0.2 and libpam-sss.
#
# Build:  docker build -t sshamble-coreos-pam-permit docs/targets/coreos-pam-permit
# Run:    docker run -d --rm --name sshamble-coreos-pam-permit -p 2224:22 sshamble-coreos-pam-permit
# Scan:   ./sshamble scan -p 2224 127.0.0.1
FROM ubuntu:16.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential libssl-dev libpam0g-dev zlib1g-dev libpam-sss \
    && rm -rf /var/lib/apt/lists/*

ADD https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-7.2p2.tar.gz /usr/src/openssh-7.2p2.tar.gz

RUN cd /usr/src \
    && tar xzf openssh-7.2p2.tar.gz \
    && cd openssh-7.2p2 \
    && ./configure --prefix=/usr --sysconfdir=/etc/ssh --with-pam \
        --with-privsep-user=sshd --with-privsep-path=/var/empty/sshd \
    && make -j"$(nproc)" \
    && make install-nokeys \
    && rm -rf /usr/src/openssh-7.2p2 /usr/src/openssh-7.2p2.tar.gz

COPY sshd_config /etc/ssh/sshd_config
COPY pam.d-sshd /etc/pam.d/sshd

RUN useradd -r -d /var/empty/sshd -s /usr/sbin/nologin sshd \
    && mkdir -p /var/empty/sshd && chmod 711 /var/empty/sshd \
    && ssh-keygen -A \
    && groupadd -g 500 core \
    && useradd -m -u 500 -g core -s /bin/bash core \
    && useradd -m -g operator -s /bin/sh operator \
    && usermod -p '!' core \
    && usermod -p '!' operator

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
