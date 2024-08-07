# SSHamble Patches for x/crypto/ssh

This repository includes a fork of the Go x/crypto package.

To maintain this fork, first rediff against upstream:

$ ./crypto.rediff.sh

This creates a file named crypto.patch.

Now resync with upstream using:

$ ./crypto.resync.sh

This applies the patch on top of upstream.

Review the changes, fix conflicts, and commit the results in ./crypto


