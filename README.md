# Cryptoconcept
---
*Draft*

## Ciphersuite
---
*Using a subset of TLS1.3 during development*

- ECDSA
  - Curve: [Nid::BRAINPOOL_P384R1](https://docs.rs/openssl/latest/openssl/nid/struct.Nid.html#associatedconstant.BRAINPOOL_P384R1)
  - Hash: [MessageDigest::sha256](https://docs.rs/openssl/latest/openssl/hash/struct.MessageDigest.html#method.sha256)
- ECDH(E)
  - Curve: [Nid::SECP384R1](https://docs.rs/openssl/latest/openssl/nid/struct.Nid.html#associatedconstant.SECP384R1)
- PBKDF2
  - [MessageDigest::sha256](https://docs.rs/openssl/latest/openssl/hash/struct.MessageDigest.html#method.sha256)
- AES-GCM
  - [Cipher::aes_256_gcm](https://docs.rs/openssl/latest/openssl/cipher/struct.Cipher.html#method.aes_256_gcm)

## Simplified cryptographic handshake
---

| Client | Server | 
|:-------|:-------|
| "Get" servers "permanent" public key (**ECDSA**) | - | 
| Load own "permanent" private key (**ECDSA**) | - |
| Generate ephemeral keypair (**ECDH**) | - |
| Generate salt (**random**) | - |
| Sign ephemeral with permanent (**ECDSA**) | - |
| Connect to server (**TCP**) | - |
| Send ephemeral public key, signature and salt (**TCP**) | - | 
| - | Receive from client (**TCP**) | 
| - | "Get" clients "permantent" public (**ECDSA**) | 
| - | Verify clients signature (**ECDSA**) | 
| - | Generate ephemeral keypair (**ECDH**) | 
| - | Load own "permanent" private key (**ECDSA**) |
| - | Sign ephemeral with permanent (**ECDSA**) | 
| - | Send ephemeral public key and signature (**TCP**) |
| Receive from server (**TCP**) | - | 
| Verify servers signature (**ECDSA**) | - | 
| Compute shared secret (**ECDH**) | Compute shared secret (**ECDH**) |
| Derive key using salt (**HKDF**) | Derive key using salt (**HKDF**) | 
| Encrypt and send (**AES**) | - |
| - | Receive and decrypt (**AES**) | 
| - | Encrypt and send (**AES**) |
| Recieve and decrypt (**AES**) | - | 

## References
---
### Web API
- [Ecdsa params](https://developer.mozilla.org/en-US/docs/Web/API/EcdsaParams)

### Datatracker
- [CheetSheet RFC8446](https://datatracker.ietf.org/doc/html/rfc8446)
- [PBKDF2 RFC8018](https://datatracker.ietf.org/doc/rfc8018/)

### OpenSSL
- [OpenSSL repository](https://github.com/openssl/openssl)
- [OpenSSL rust bindings](https://docs.rs/openssl/latest/openssl/index.html)

### Mbed-TLS
- [Mbed-TLS repository](https://github.com/Mbed-TLS/mbedtls)
- [Mbed-TLS rust bindings](https://docs.rs/mbedtls/latest/mbedtls/index.html)

### wolfSSL
- [wolfSSL repository](https://github.com/wolfSSL/wolfssl)
- [wolfSSL rust bindings](https://docs.rs/wolfssl/latest/wolfssl/index.html)

### ESP32
- [ESP32 Series Datasheet](https://www.espressif.com/sites/default/files/documentation/esp32_datasheet_en.pdf)
- [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32/index.html)
- [ESP-IDF TLS](https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32/api-reference/protocols/esp_tls.html)
- [ESP-IDF Mbed TLS](https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32/api-reference/protocols/mbedtls.html)
- [ESP-IDF repository](https://github.com/espressif/esp-idf/tree/v5.5)
- [ESP-wolfSSL repository](https://github.com/espressif/esp-wolfssl)

