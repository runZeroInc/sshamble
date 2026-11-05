#!/bin/sh
# Build-time setup for Dockerfile.alpine. Fixture passwords only.
set -eux

case "$VARIANT" in
patched)
	apk add --no-cache openssh-server
	sshd=/usr/sbin/sshd
	usepam=
	;;
vuln | nohash | pam)
	apk add --no-cache build-base curl linux-headers openssl-dev zlib-dev
	configure_pam=
	usepam=
	if [ "$VARIANT" = pam ]; then
		apk add --no-cache linux-pam linux-pam-dev
		configure_pam=--with-pam
		usepam='UsePAM yes'
		mkdir -p /etc/pam.d
		printf 'auth include base-auth\naccount include base-account\npassword include base-password\nsession include base-session\n' > /etc/pam.d/sshd
	fi
	cd /tmp
	curl -fsSL -o openssh.tar.gz "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-$OPENSSH_VERSION.tar.gz"
	echo "$OPENSSH_SHA512  openssh.tar.gz" | sha512sum -c -
	tar -xzf openssh.tar.gz
	cd "openssh-$OPENSSH_VERSION"
	./configure --prefix=/usr --sysconfdir=/etc/ssh --with-privsep-path=/var/empty $configure_pam
	make -j"$(nproc)"
	make install-nokeys
	cd /
	rm -rf /tmp/openssh*
	mkdir -p /var/empty
	sshd=/usr/sbin/sshd
	;;
*)
	echo "unknown VARIANT $VARIANT" >&2
	exit 1
	;;
esac
ssh-keygen -A

# First match wins in sshd_config, so put the overrides ahead of any Include.
# PerSourcePenalties would refuse the scanner after a few failed logins.
printf 'PasswordAuthentication yes\nPermitRootLogin yes\nPerSourcePenalties no\n%s\n' "$usepam" > /tmp/head
grep -v '^UsePAM' /etc/ssh/sshd_config >> /tmp/head
mv /tmp/head /etc/ssh/sshd_config
mkdir -p /run/sshd
"$sshd" -t 2>/dev/null || sed -i '/^PerSourcePenalties/d' /etc/ssh/sshd_config # added in 9.8
"$sshd" -t

# root is already "*" on current Alpine images; busybox adduser -D writes "!".
adduser -D -s /bin/sh alpine
sed -i -e 's/^root:[^:]*:/root:*:/' -e 's/^alpine:[^:]*:/alpine:*:/' /etc/shadow
if [ "$VARIANT" != nohash ]; then
	adduser -D -s /bin/sh tester
	echo 'tester:sshhole-fixture' | chpasswd -c sha512
fi

printf '#!/bin/sh\nexec %s -D -e\n' "$sshd" > /start-sshd
chmod 0755 /start-sshd
"$sshd" -V 2>&1 || true
grep -E '^(root|alpine|tester):' /etc/shadow | cut -c1-24
