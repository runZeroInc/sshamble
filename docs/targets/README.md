# Vulnerable test targets

Each subdirectory contains a self-contained Dockerfile that builds a target
vulnerable to one of sshamble's checks. These exist so that check development
and regression testing do not depend on rediscovering fiddly container
configuration every time.

## Layout

```
docs/targets/<check-name>/
    README.md
    Dockerfile
    Dockerfile.patched   (optional: a non-vulnerable control)
```

The directory name should match the check name (e.g. `musl-crypt-star` for
`vuln-musl-crypt-star`, with the `vuln-` prefix dropped).

## Usage

Build and run a target, then scan it:

```console
$ docker build -t sshamble-musl-crypt-star docs/targets/musl-crypt-star
$ docker run -d --rm --name sshamble-musl-crypt-star -p 2222:22 sshamble-musl-crypt-star
$ ./sshamble scan -u alice -p 2222 127.0.0.1
$ docker stop sshamble-musl-crypt-star
```

## Targets

| Directory | Check | Vulnerability |
|-----------|-------|---------------|
| [musl-crypt-star](musl-crypt-star/) | `vuln-musl-crypt-star` | OpenSSH < 10.6p2 on musl libc without PAM accepts any >256-byte password for accounts whose hash is `*` ([sshhole.com](https://sshhole.com/)) |

## Adding a new target

1. Create `docs/targets/<check-name>/Dockerfile` and a `README.md` that
   explains how to build the target, run the check against it, and confirm
   both the finding and the absence of a finding on a patched control.
2. Keep the image minimal and pinned (specific base image tag, not `latest`),
   so the target stays vulnerable as upstream packages are patched.
3. Document the vulnerable condition in a comment at the top of the
   Dockerfile: what software version, what configuration, and why it is
   vulnerable.
4. Add a row to the table above.
