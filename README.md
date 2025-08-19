# sshamble

SSHamble is a research tool for SSH implementations that includes:

* Interesting attacks against authentication
* Post-session authentication attacks
* Pre-authentication state transitions
* Authentication timing analysis
* Post-session enumeration

This project is a work-in-progress and likely to change quickly.

You can reach our team via research[α𝓽]runZero.com.

https://SSHamble.com/


## Installation

Binaries are available from the [releases page](https://github.com/runZeroInc/sshamble/releases).

*(Note: on MacOS, you will likely have to disable Gatekeeper for this binary, with `sudo xattr -rd com.apple.quarantine ./sshamble`. This is not an invitation to violate your asset owner's security policy.)*

To build SSHamble from source, ensure that you have a recent version of Go (1.24+) installed.

You can use Go to install a binary into the `bin` directory in your GOPATH.

If you are using macOS, you may run into errors at runtime unless you disable CGO before building:
```shell
$ export CGO_ENABLED=0
```

```shell
$ go install github.com/runZeroInc/sshamble@latest
```

To build from source locally:

```shell
$ git clone https://github.com/runZeroInc/sshamble
$ cd sshamble
$ go build -o sshamble
$ ./sshamble -h
```

To enable [badkeys](https://badkeys.info) support, run `sshamble badkeys-update` first, then scan.
```shell
$ git clone https://github.com/runZeroInc/sshamble
$ cd sshamble
$ go generate ./...
$ go build -o sshamble
$ ./sshamble badkeys-update
```

## Usage

```console
$ ./sshamble -h

▀██▄  ▀███████████████████████████████████████████████████████████████████████████████████████████
  ▀██▄
    ▀██▄     ▄████████  ▄████████  ██     ██  ▄███████▄  ▄████████▄  ████████▄  ██        ▄███████
      ▀██▄   ██         ██         ██     ██  ██     ██  ██  ██  ██  ██     ██  ██        ██
        ███  ▀███████▄  ▀███████▄  █████████  █████████  ██  ██  ██  █████████  ██        ████████
      ▄██▀          ██         ██  ██     ██  ██     ██  ██  ██  ██  ██     ██  ██        ██
    ▄██▀     ████████▀  ████████▀  ██     ██  ██     ██  ██  ██  ██  ████████▀   ▀██████  ▀███████
  ▄██▀
▄██▀  ▄███████████████████████████████████████████████████████████████████████████████████████████

An exploration tool for (in)secure shell services.


Start a network scan using:

$ ./sshamble scan -o results.jsonl 192.168.0.0/24

Analyze the results using:

$ ./sshamble analyze -o results-directory results.jsonl

Usage:
  sshamble [command]

Available Commands:
  analyze        Analyzes a scan JSON output file and buckets results
  badkeys-update Updates the badkeys.info blocklist cache.
  help           Help about any command
  scan           Enumerates a set of targets for SSH capabilities and exposures

Flags:
  -h, --help   help for sshamble

Use "sshamble [command] --help" for more information about a command.
```

## Scans

```console
$ ./sshamble scan -h
Enumerates a set of targets for SSH capabilities and exposures

Usage:
  sshamble scan [-p 22] [-u root,admin] [-o scan.jsonl] [-l scan.log] [--log-level trace] 192.168.0.0/24 ... [flags]

Flags:
      --categories string                     The list of categories to include. (default "bypass,gssapi,hostkey,keyboard,password,pubkey,userenum,vuln")
      --checks string                         The list of checks to run. Non-default ("userenum-none-timing,userenum-password-timing,userenum-pubkey-timing,vuln-exec-skip-auth,vuln-exec-skip-userauth") (default "badkeys-blocklist,gssapi-any,keyboard-any,keyboard-empty,keyboard-null,keyboard-user,password-any,password-change-empty,password-change-null,password-empty,password-null,password-user,pubkey-any,pubkey-bulkhalf,pubkey-hunt,pubkey-user,skip-auth,skip-auth-method-empty,skip-auth-method-null,skip-auth-none,skip-auth-pubkeyany,skip-auth-success,skip-ssh-userauth,vuln-generic-env,vuln-gogs-env,vuln-ruckus-password-escape,vuln-softserve-env,vuln-tcp-forward")
      --client-version string                 The client version string to send (default "OpenSSH_9.8p1")
      --config string                         config file (default is $HOME/.sshamble.json)
  -h, --help                                  help for scan
  -i, --input-targets string                  The optional file to read targets from
  -I, --interact string                       Open an interactive shell for the 'first', 'all', or 'none' sessions (default "none")
      --interact-auto string                  A comma-separated set of commands to run in the interactive session (default "pty,shell")
  -l, --log string                            The file to write logs to (default is stderr) (default "-")
  -L, --log-level string                      The log level to write (trace,debug,info,warn,error) (default "info")
  -m, --max-connections uint                  The maximum number of concurrent connections (default 5000)
      --one-session-only                      Only open one session per target
  -o, --output string                         The destination file for JSON output (default "stdout")
      --password string                       An optional password to try for authentication
      --password-file string                  An optional file with clear-text passwords to try for authentication
  -p, --ports string                          The list of ports to check when not specified with the target (comma-separated) (default "22")
      --pprof string                          Start a Go pprof debug listener on the provided port
      --private-key string                    The optional file containing a private key for authentication
      --private-key-passphrase string         The optional passphrase for a private key file
      --pubkey-bulk-limit uint                The number of pubkey half-auths to test for max attempts (default 10)
      --pubkey-hunt-conn-limit uint           The number of public keys to test in each connection (default 250000)
      --pubkey-hunt-file string               The optional file containing public keys to hunt
      --retries uint                          The retry count for subsequent failed connections after an initial success (default 2)
      --session-poke string                   A byte sequence sent to sessions to elicit further responses (hex or ascii) (default "\\x0a\\x0d\\r\\n")
      --skip-versions string                  A regular expression of SSH versions to skip (ex: '(?i)openssh|dropbear)'
      --timeout uint                          The number of seconds to wait for a target to respond (default 5)
      --userenum-max-per-session-count uint   The maximum number of authentication atempts per session (default 1023)
      --userenum-test-count uint              The number of tests to apply during username enumeration (default 2500)
  -u, --users string                          The list of usernames to test on each target (comma-separated) (default "root")
```
