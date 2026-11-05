# vuln-musl-crypt-star test targets

This directory builds Docker controls for the `vuln-musl-crypt-star` check:
one vulnerable target and four negative controls.

## Background

OpenSSH sshd built against musl libc without PAM accepts any password of
257 to 1024 bytes for a valid user whose shadow field is the literal `*`,
provided another account carries a `$5$` or `$6$` hash. A one-character
field gives `sys_auth_passwd()` a NULL salt, so `pick_salt()` borrows the
prefix of another account's hash. musl's SHA-256/512 `crypt(3)` returns the
string `"*"` for keys over 256 bytes, and sshd compares that return value
against the stored `"*"` with `strcmp`. Accounts locked with `!` are not
affected. OpenSSH 10.6p2 (2026-11-05) rejects short stored hashes before
calling `crypt(3)`, and Alpine backported that fix as `pw.patch` to 3.20,
3.22 and 3.24 without changing the banner.

The first password attempt on a connection always fails when `/etc/shadow`
is present. musl's `getspnam()` returns a pointer into a static buffer,
`pick_salt()` calls it for every account and zeroes the hash it copies, so
`sys_auth_passwd()` compares against an empty string. `pick_salt()` caches
the salt, so later attempts on the same connection compare against `*`. A
probe that sends one long password per connection never finds the bug.

Reference: [sshhole.com](https://sshhole.com/)

## How the check works

The check is enabled by default and runs whenever all of the following hold:

1. The server banner parses as OpenSSH older than 10.6p2. Non-OpenSSH
   banners, 10.6p2 and later, and OpenSSH banners with no version number are
   skipped without making a connection.
2. The server advertises `password` authentication.

On one connection it sends a 256-byte random control password, which musl
still hashes normally and which must be rejected, then a 257-byte random
password, then a 1024-byte one if 257 fails. A `Too many authentication
failures` disconnect at `MaxAuthTries` counts as a rejected attempt. The
check reports a finding only when the control is rejected and a longer
password is accepted, and runs `id; uname -a; ls /lib/ld-musl-*; head -3
/etc/os-release` on the session as proof. A server that accepts the control
password belongs to the `password-any` check instead.

A second connection then authenticates with the accepted password alone,
resending it once if the first attempt fails. When that opens a session the
password is cached as the session credential so `-I first` and `-I all`
reconnect with it, and the proof records which attempt succeeded.

## Files

| File | Purpose |
|------|---------|
| `Dockerfile.alpine` | Alpine (musl). `VARIANT` picks the setup, see below. |
| `Dockerfile.debian` | Debian 13 with glibc, PAM off, so libc is the only difference. Not vulnerable. |
| `setup-alpine.sh` | Build-time setup for `Dockerfile.alpine`. |
| `run.sh` | Builds the images and starts or stops all five containers. |

Alpine variants:

| Variant | Build | Expected |
|---------|-------|----------|
| `vuln` | Upstream OpenSSH 10.3p1 from the tarball, no PAM, `*` accounts plus one SHA-512 account | Vulnerable (root, alpine) |
| `nohash` | Same build, but no account has a `$5$`/`$6$` hash for `pick_salt()` to borrow | Clean |
| `pam` | Same build with `--with-pam` and `UsePAM yes` | Clean |
| `patched` | Alpine's `openssh-server` package with `pw.patch` | Clean |

Alpine's own packages are all patched now, so the unpatched builds come from
the upstream tarball, pinned to the sha512 in Alpine's APKBUILD. Pass
`OPENSSH_VERSION` and `OPENSSH_SHA512` as build arguments to test another
release; 9.7p1 on Alpine 3.20 behaves the same way.

All images use the same accounts:

| User | Shadow field | Notes |
|------|--------------|-------|
| root | `*` | Affected account |
| alpine | `*` | Affected account |
| tester | `$6$...` | Provides the salt that `pick_salt()` borrows (absent in `nohash`) |

## Setup

Build the sshamble binary and start the containers from the repository root:

```console
$ go build -o sshamble .
$ docs/targets/musl-crypt-star/run.sh up
```

`BIND` (default 127.0.0.1) and `BASE_PORT` (default 2201) set the published
ports, `ALPINE_VERSION` (default 3.24) picks the Alpine release:

| Port | Container | Expected |
|------|-----------|----------|
| 2201 | `musl-crypt-star-alpine-vuln` | vulnerable (root, alpine) |
| 2202 | `musl-crypt-star-alpine-nohash` | clean |
| 2203 | `musl-crypt-star-alpine-pam` | clean |
| 2204 | `musl-crypt-star-alpine-patched` | clean |
| 2205 | `musl-crypt-star-debian-glibc` | clean |

## Verify the check reports the vulnerable target

```console
$ ./sshamble scan -u root,alpine,tester -p 2201 --checks vuln-musl-crypt-star -o vuln.json 127.0.0.1
```

The log should contain, for root and alpine only:

```
level=warning msg="127.0.0.1:2201 vuln-musl-crypt-star accepted a 257-byte random password for user root"
```

The JSON records for those users carry `sessionMethod` set to
`vuln-musl-crypt-star` and a `vulns` entry whose proof names the control
and trigger lengths, the proof command output, and the attempt on which the
fresh connection logged in (attempt 2 on these images).

## Verify the check does not report the controls

```console
$ for p in 2202 2203 2204 2205; do ./sshamble scan -u root,alpine -p $p --checks vuln-musl-crypt-star -L debug 127.0.0.1; done
```

Each run logs the check starting and stopping because every trigger
password was rejected, and the JSON records carry no `vulns` entry:

```
level=debug msg="127.0.0.1:2204 vuln-musl-crypt-star not vulnerable for user root: every trigger password was rejected (stage ssh-userauth: authentication failed: auth-failed)"
```

## Verify the version gate

Point the check at any OpenSSH 10.6p2 or newer server, or any non-OpenSSH
server, with `-L debug`. The log shows the skip and no password attempts
are made:

```
level=debug msg="HOST:PORT vuln-musl-crypt-star skipped: server version \"SSH-2.0-OpenSSH_10.6p2\" is not a vulnerable OpenSSH release"
```

## Verify the interactive session

The cached password is reused to open a new session for interaction:

```console
$ ./sshamble scan -u root -p 2201 --checks vuln-musl-crypt-star -I first --interact-auto "exec id" 127.0.0.1
```

The output ends with the command result:

```
uid=0(root) gid=0(root) groups=0(root)
```

## Verify manually with ssh

The first attempt on a connection fails and the second succeeds, so send
the long password twice:

```console
$ python3 -c "print('A'*300)" > longpass.txt
$ ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2201 root@127.0.0.1 id
```

Paste the contents of `longpass.txt` at both password prompts. On the
controls every attempt is rejected.

## Unit tests

The Go tests start an in-process SSH server that models musl, rejecting the
first attempt on every connection and accepting longer passwords after
that, and cover the same cases without Docker: the finding with and without
the first-attempt quirk, `MaxAuthTries 2`, no finding when the long
passwords are rejected, no finding when any password is accepted, no
connection for fixed or non-OpenSSH banners, and reuse of the cached
credential for interaction.

```console
$ go test ./cmd/ -run MuslCryptStar -v
```

## Cleanup

```console
$ docs/targets/musl-crypt-star/run.sh down
```
