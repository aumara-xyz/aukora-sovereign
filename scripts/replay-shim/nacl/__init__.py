# SPDX-License-Identifier: AGPL-3.0-or-later
"""A stand-in for the three PyNaCl calls tools/verify.py makes, for scripts/verifier-vectors.py ONLY.

tools/verify.py accepts no Ed25519 provider but PyNaCl. Where PyNaCl is not installed the replay would have to skip every
case that checks a signature, which is most of the bundle cases, and the Python twin would go unchecked on them. The
replay puts this folder first on the Python engine's path instead. It verifies; it never signs. It is plain RFC 8032
arithmetic, slow and not constant-time, and it is never used by anything that is not the replay: the shipped verifier does
not import it and the node does not run it. Its own self-test (RFC 8032, section 7.1) runs before the replay relies on it.
"""
