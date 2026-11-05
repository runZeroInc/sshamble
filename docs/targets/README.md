# Vulnerable test targets

Each subdirectory contains a self-contained Dockerfile that builds a target
vulnerable to one of sshamble's checks, a README that explains how to verify
the check against it, and where possible a patched control image that the
check must not flag. These exist so that check development and regression
testing do not depend on rediscovering fiddly container configuration every
time.

## Layout

```
docs/targets/<check-name>/
    README.md
    Dockerfile
    Dockerfile.patched   (optional: a non-vulnerable control)
```

The directory name should match the check name with the `vuln-` prefix
dropped (e.g. `coreos-pam-permit` for `vuln-coreos-pam-permit`).

## Targets

| Directory | Check | Vulnerability |
|-----------|-------|---------------|
| [coreos-pam-permit](coreos-pam-permit/) | `vuln-coreos-pam-permit` | CoreOS Linux Alpha 1045.0.0 and 1047.0.0 PAM stack falls through to `pam_permit`, so any password logs in as any account (CVE-2016-4455) |

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
