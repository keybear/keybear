# Cryptography

Whenever a device is registered public [X25519](https://github.com/dalek-cryptography/x25519-dalek) keys are exchanged between the server and the client. All communication from this point on is encrypted with the [ChaCha20Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) cipher using a generated X25519 shared key as the ChaCha20 key.
