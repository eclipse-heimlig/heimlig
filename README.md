# Sindri

Sindri is a Hardware Security Modules (HSM) written in Rust.
It provides cryptographic services to clients running on other cores:

- Key generation and secure storage
- Key use (encryption, decryption, signing, verification) without revealing key material
- Cryptographically secure pseudorandom number generator (CSPRNG)

Unlike software based cryptographic providers, an HSM preserves the secrecy of the stored key material even
if hte users of the HSM are compromised.     

## Status

Sindri is still in early development and is currently in the prototyping phase.

## Supported Cryptographic Algorithms

- [ChaCha20](https://crates.io/crates/rand_chacha) based cryptographically secure pseudorandom number generator (CSPRNG) seeded by the hardware.