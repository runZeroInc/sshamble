# Vulnerable test targets

Each subdirectory contains a self-contained Dockerfile that builds a target
vulnerable to one of sshamble's checks. These exist so that check development
and regression testing do not depend on rediscovering fiddly container
configuration every time.

## Layout

```
docs/targets/<check-name>/
    README.md
    Dockerfile           (or one Dockerfile per platform, with a run.sh)
    Dockerfile.patched   (optional: a non-vulnerable control)
```

The directory name should match the check name (e.g. `sshhole` for
`vuln-sshhole`, with the `vuln-` prefix dropped).

## Usage

Build and run a target, then scan it:

```console
$ docs/targets/sshhole/run.sh up
$ ./sshamble scan -u root -p 2201 127.0.0.1
$ docs/targets/sshhole/run.sh down
```

## Demos

`record-demo.sh <target>` records a scan of a running target with asciinema
and renders it with agg, writing `demo.cast` and `demo.gif` into the
target's directory. It needs asciinema 3, agg, jq, expect and a built
`./sshamble` in the repository root.

## Targets

| Directory | Check | Vulnerability |
|-----------|-------|---------------|
| [coreos-pam-permit](coreos-pam-permit/) | `vuln-coreos-pam-permit` | CoreOS Linux Alpha 1045.0.0 and 1047.0.0 PAM stack falls through to `pam_permit`, so any password logs in as any account (CVE-2016-4455) |
| [sshhole](sshhole/) | `vuln-sshhole` | OpenSSH < 10.6p2 on musl libc without PAM accepts any 257 to 1024 byte password for accounts whose shadow field is `*` ([sshhole.com](https://sshhole.com/)) |

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
