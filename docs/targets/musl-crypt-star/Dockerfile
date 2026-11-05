# Vulnerable target for the vuln-musl-crypt-star check (sshhole.com).
#
# OpenSSH 9.7p1 built from source against musl libc without PAM.
# With no /etc/shadow file, sshd reads the account hash directly from
# /etc/passwd; an account whose hash field is "*" (not "!") can be
# logged into with any password longer than 256 bytes, because musl
# crypt(3) returns the literal string "*" for over-long passwords and
# sshd compares it against the stored "*" with strcmp.
#
# We build from source because Alpine backported the upstream fix
# (MIN_PASSWORD_HASH_LEN) into its openssh packages on 2026-11-05,
# so `apk add openssh-server` now installs a patched binary even
# though the version string still reads "OpenSSH_9.7".
#
# Build:  docker build -t sshamble-musl-crypt-star docs/targets/musl-crypt-star
# Run:    docker run -d --rm --name sshamble-musl-crypt-star -p 2222:22 sshamble-musl-crypt-star
# Scan:   ./sshamble scan -u alice -p 2222 127.0.0.1
FROM alpine:3.20 AS build

RUN apk add --no-cache build-base zlib-dev openssl-dev openssl-libs-static zlib-static

RUN wget -q https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.7p1.tar.gz \
    && tar xzf openssh-9.7p1.tar.gz \
    && cd openssh-9.7p1 \
    && ./configure --prefix=/usr --sysconfdir=/etc/ssh --without-pam --with-md5-passwords \
    && make -j$(nproc) sshd ssh-keygen \
    && install -m 755 sshd /usr/sbin/sshd \
    && install -m 755 ssh-keygen /usr/bin/ssh-keygen

FROM alpine:3.20

COPY --from=build /usr/sbin/sshd /usr/sbin/sshd
COPY --from=build /usr/bin/ssh-keygen /usr/bin/ssh-keygen

RUN apk add --no-cache libcrypto3 zlib \
    && mkdir -p /etc/ssh \
    && printf 'PasswordAuthentication yes\nPermitRootLogin yes\nSubsystem sftp internal-sftp\n' > /etc/ssh/sshd_config \
    && ssh-keygen -A \
    && adduser -D -s /bin/sh alice \
    && adduser -D -s /bin/sh bob \
    && sed -i \
        -e 's/^root:x:/root:*:/' \
        -e 's/^alice:x:/alice:*:/' \
        -e 's|^bob:x:|bob:$6$rounds=5000$salt$placeholder:|' \
        /etc/passwd \
    && rm -f /etc/shadow \
    && chmod 644 /etc/passwd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
