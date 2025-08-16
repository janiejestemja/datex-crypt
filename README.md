# ECC
---
> *Elliptic Curve Cryptography*

## Ciphersuite
---
> *Replacement of RSA with ECC*

> [!Tip]
> [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
>
> [OpenSSL crate docs](https://docs.rs/openssl/latest/openssl/index.html)

### ECDSA
---
> *Elliptic Curve Digital Signature Algorithm*

- Curve: [Nid::BRAINPOOL_P384R1](https://docs.rs/openssl/latest/openssl/nid/struct.Nid.html#associatedconstant.BRAINPOOL_P384R1)
- Hash: [MessageDigest::sha256](https://docs.rs/openssl/latest/openssl/hash/struct.MessageDigest.html#method.sha256)

> [!Note]
> Signature and verification.

### ECIEC
---
> *Elliptic Curve Integrated Encryption Scheme*

- AES-GCM: [Cipher::aes_256_gcm](https://docs.rs/openssl/latest/openssl/cipher/struct.Cipher.html#method.aes_256_gcm)

> [!Note]
> Hybrid Encryption.
