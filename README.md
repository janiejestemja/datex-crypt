# Protocol
---

Notation 
- msg = message to encrypt
- k_msg = ephemeral symmetric key for this message
- ek_i = ephemeral key for recipient i
- pk_i, sk_i = long term public/private key of recipient i
- wrap(k_msg, ss) = key wrap (aes-kw) using shared secret ss
- enc(k_msg, msg) = symmetric encryption of message with k_msg (aes-gcm)
- dh(pri, pub) = (ec) diffie-hellman operation

**Sender**
1. generate eph symmetric key
```
k_msg <- random key (128/256 bits)
```
2. encrypt msg
```
C <- enc(k_msg, msg)
```
3. For each recipient i:

  - 1. generate recipient specific ephemeral keypar

  ```
  (ek_i_pri, ek_i_pub) <- ephemeral key pair
  ```

  - 2. Deriva a shared secred with recipients long term public key
  ```
  ss_i <- dh(ek_i_pri, pk_i)
  ```

  - 3. Wrap the message key k_msg with the shared secret
  ```
  WrappedKey_i <- wrap(k_msg, ss_i)
  ```

  - 4. Prepaire payload
  ```
  (ek_i_pub, WrappedKey_i, cipher)
  ```

4. Send each recpipient their payload


**Recipient i**
1. recieve tuple 
```
(ek_i_pub, WrappedKey_i, cipher)
```
2. derive shared secret using long term private key
```
ss_i <- dh(sk_i, ek_i_pub)
```
3. Unwrap the message key
```
k_msg <- unwrap(WrappedKey_i, ss_i)
```
4. Decrypt the message
```
msg <- dec(k_msg, cipher)
```

**Properties**
- Forward secrecy
  - each recipients eph key is destroyed after use, thus compromise of the long-term private key later does not expose past messages
- multi recipient
  - each recipient gets a unique eph key + wrapped key, thus the message ciphertext is only encrypted once
- no meta leak compromise
  - only the fact thtat the same message was sent to multiple recipients might be inferred - keys remain secure
