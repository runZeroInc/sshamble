# Bad Keys

This is a partial Go implementation of [Hanno Böck](https://hboeck.de/)'s [badkeys project](https://badkeys.info/).

The major differences include:

  * The known key blocklist and lookup tables are baked into the Go package and updated through a generator. This data is still sourced from badkeys, but reformatted for fast lookups and smaller size. This implementation is likely to change soon.

  * This project does not implement weak prime detection.

  * This project is missing other badkeys detections:
    * Fermat
    * Patterns
    * ROCA
    * RSA Invalid
    * RSA Warnings
    * Shared Primes
    * Small Factors
    * XZ Backdoor