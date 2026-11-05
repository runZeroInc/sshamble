#!/bin/sh
# Record a demo of one check against its Docker target as an asciinema cast
# and a gif in docs/targets/<target>/.
#
#   docs/targets/record-demo.sh sshhole
#   docs/targets/record-demo.sh coreos-pam-permit
#
# Needs asciinema (3.x), agg, jq, expect and a built ./sshamble in the
# repository root. Start the target first (see the target's README);
# DEMO_PORT overrides the port the demo scans.
set -eu

target=${1:-}
case "$target" in
sshhole)
	port=${DEMO_PORT:-2201}
	users=root,alpine,tester
	check=vuln-sshhole
	;;
coreos-pam-permit)
	port=${DEMO_PORT:-2224}
	users=root
	check=vuln-coreos-pam-permit
	;;
*)
	echo "usage: $0 sshhole|coreos-pam-permit" >&2
	exit 1
	;;
esac

root=$(cd "$(dirname "$0")/../.." && pwd)
out="$root/docs/targets/$target"
cast="$out/demo.cast"
gif="$out/demo.gif"
json="$target.json"
script=$(mktemp)
trap 'rm -f "$script" "$script.exp" "$root/$json"' EXIT

# Drives the interactive shell that -I first opens: waits for the remote
# prompt, types uname -a, and leaves the recording on the output.
cat > "$script.exp" <<'EOF'
set timeout 20
log_user 0
spawn ./sshamble scan -u root -p $env(DEMO_PORT) --checks $env(DEMO_CHECK) -I first -o /dev/null 127.0.0.1
log_user 1
expect -re {[$#] $}
after 800
foreach c [split "uname -a" ""] { send -- $c; expect -timeout 1 -re ".+"; after 70 }
send "\r"
expect -re {[$#] $}
after 2000
EOF

# The recorded session: a fake prompt, each command typed out, then run.
cat > "$script" <<EOF
#!/bin/sh
cd "$root"
type_cmd() {
	printf '\033[1;32m\$\033[0m '
	printf '%s\n' "\$1" | fold -w1 | while IFS= read -r ch; do
		printf '%s' "\$ch"
		sleep 0.03
	done
	printf '\n'
	sleep 0.4
}
run() {
	type_cmd "\$1"
	eval "\$1"
	sleep 1.5
}
printf '\033[1m# %s against the docs/targets/%s Docker target\033[0m\n\n' "$check" "$target"
sleep 1
run "./sshamble scan -u $users -p $port --checks $check -o $json 127.0.0.1"
run "jq -c '{user, version, sessionMethod, vulns: [.vulns[]? | .id]}' $json"
run "jq -rn 'first(inputs | select(.vulns)) | .vulns[0].proof' $json"
type_cmd "./sshamble scan -u root -p $port --checks $check -I first -o /dev/null 127.0.0.1"
DEMO_PORT=$port DEMO_CHECK=$check expect "$script.exp"
EOF

rm -f "$cast"
asciinema rec --headless --window-size 110x32 --idle-time-limit 2 \
	--title "sshamble $check" --command "sh $script" "$cast"
agg --font-size 15 --idle-time-limit 2 --last-frame-duration 15 "$cast" "$gif"
ls -l "$cast" "$gif"
