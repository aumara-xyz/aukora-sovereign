# SPDX-License-Identifier: AGPL-3.0-or-later
"""A stand-in for the few `cryptography` calls tools/verify.py makes to check an ES256 owner assertion, for
scripts/verifier-vectors.py ONLY.

tools/verify.py needs the `cryptography` package for C5 owner signatures and refuses with `crypto-unavailable` without it, so
the replay could not run the Python twin's whole owner path. Where the package is not installed the replay puts this folder
on the Python engine's path. It verifies a P-256 signature over SHA-256 and reads a public point; it never signs and offers
nothing else of `cryptography`. It is plain integer arithmetic (p256_ref.py), slow and not constant-time, and used by nothing
but the replay: the shipped verifier does not import it and the node does not run it.
"""
