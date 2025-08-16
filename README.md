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

#### Web Crypto API
- [EcdsaParams](https://developer.mozilla.org/en-US/docs/Web/API/EcdsaParams)

#### OpenSSL crate
- [Signer/Verifier](https://docs.rs/openssl/latest/openssl/sign/struct.Signer.html)
- Curve: [Nid::BRAINPOOL_P384R1](https://docs.rs/openssl/latest/openssl/nid/struct.Nid.html#associatedconstant.BRAINPOOL_P384R1)
- Hash: [MessageDigest::sha256](https://docs.rs/openssl/latest/openssl/hash/struct.MessageDigest.html#method.sha256)

> [!Note]
> Signature and verification.

### ECIEC
---
> *Elliptic Curve Integrated Encryption Scheme*

#### Web Crypto API
- [EcdhKeyDeriveParams](https://developer.mozilla.org/en-US/docs/Web/API/EcdhKeyDeriveParams)
- [HkdfParams](https://developer.mozilla.org/en-US/docs/Web/API/HkdfParams)
- [AesGcmParams](https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams)
  
#### OpenSSL crate
- [ECDH KD](https://docs.rs/openssl/latest/openssl/derive/index.html): [Nid::BRAINPOOL_P384R1](https://docs.rs/openssl/latest/openssl/nid/struct.Nid.html#associatedconstant.BRAINPOOL_P384R1)
- [HKDF](https://docs.rs/openssl/latest/openssl/pkey_ctx/struct.HkdfMode.html): [&Md::sha256()](https://docs.rs/openssl/latest/openssl/md/struct.Md.html)
- [AES-GCM](https://docs.rs/openssl/latest/openssl/symm/index.html): [Cipher::aes_256_gcm](https://docs.rs/openssl/latest/openssl/cipher/struct.Cipher.html#method.aes_256_gcm)

> [!Note]
> Hybrid Encryption.
