#!/bin/sh
# Build, start, or stop the vuln-sshhole control targets.
#
#   ./run.sh up      build the images and start the containers
#   ./run.sh down    stop and remove the containers
#
# BIND (default 127.0.0.1) and BASE_PORT (default 2201) set the published
# ports, ALPINE_VERSION (default 3.24) picks the Alpine release.
#
#   BASE_PORT+0  sshhole-alpine-vuln     expected vulnerable (root, alpine)
#   BASE_PORT+1  sshhole-alpine-nohash   expected clean, no hash to borrow a salt from
#   BASE_PORT+2  sshhole-alpine-pam      expected clean, PAM build
#   BASE_PORT+3  sshhole-alpine-patched  expected clean, Alpine package with pw.patch
#   BASE_PORT+4  sshhole-debian-glibc    expected clean, glibc
set -eu
cd "$(dirname "$0")"

BIND=${BIND:-127.0.0.1}
BASE_PORT=${BASE_PORT:-2201}
ALPINE_VERSION=${ALPINE_VERSION:-3.24}
VARIANTS="vuln nohash pam patched"

up() {
	port=$BASE_PORT
	for variant in $VARIANTS; do
		docker build -q -t "sshhole-alpine-$variant:$ALPINE_VERSION" \
			--build-arg ALPINE_VERSION="$ALPINE_VERSION" --build-arg VARIANT="$variant" \
			-f Dockerfile.alpine .
		docker run -d --rm --name "sshhole-alpine-$variant" -p "$BIND:$port:22" \
			"sshhole-alpine-$variant:$ALPINE_VERSION"
		port=$((port + 1))
	done
	docker build -q -t sshhole-debian-glibc -f Dockerfile.debian .
	docker run -d --rm --name sshhole-debian-glibc -p "$BIND:$port:22" sshhole-debian-glibc
	for variant in $VARIANTS; do
		name=sshhole-alpine-$variant
		printf '%s %s\n' "$name" "$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name")"
	done
	printf '%s %s\n' sshhole-debian-glibc "$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' sshhole-debian-glibc)"
}

down() {
	for name in $(for v in $VARIANTS; do echo "sshhole-alpine-$v"; done) sshhole-debian-glibc; do
		# Where AppArmor blocks docker stop/kill, ending sshd (PID 1) from inside still works.
		docker rm -f "$name" >/dev/null 2>&1 || docker exec "$name" kill -TERM 1 >/dev/null 2>&1 || true
	done
}

case "${1:-}" in
up) up ;;
down) down ;;
*)
	echo "usage: $0 up|down" >&2
	exit 1
	;;
esac
