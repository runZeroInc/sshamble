# Bad Keys

This is a partial Go implementation of [Hanno Böck](https://hboeck.de/)'s [badkeys project](https://badkeys.info/).

The major differences include:

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