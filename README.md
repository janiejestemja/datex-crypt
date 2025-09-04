## Workflow
---
### Overview
---
So how do i protect our secrets from... well... me?

Sender
1. Generate symmetric message-key
2. Encrypt something (e.g. a message)
3. For each recipient:
  - 3.1 Generate recipient specific ephemeral keypair
  - 3.2 Derive a shared secred with recipients long term public key
  - 3.3 Wrap the message-key with the shared secret as key encryption key (KEK)
  - 3.4 Prepare payload (containing ephemeral public key, wrapped key, encrypted message)
  - 3.5 Destroy all ephemeral keypairs (forward security)
4. Send each recpipient their payload

Recipient
1. Receive payload 
2. Derive shared secret using long term private and ephemeral public
3. Unwrap the message key
4. Decrypt the message

### Details
---
Notation 
- `msg` = message to encrypt
- `k_msg` = ephemeral symmetric key for this message
- `ek_i` = ephemeral key for recipient `i`
- `pk_i`, `sk_i` = long-term public/private key of recipient `i`
- `wrap(k_msg, ss)` = key wrap using shared secret `ss`
- `enc(k_msg, msg)`= symmetric encryption of message with `k_msg` 
- `dh(pri, pub)` = (ec) diffie-hellman operation

**Sender**
1. Generate ephemeral symmetric key `k_msg` 
```
random key (128/256 bits) -> k_msg
```

2. Encrypt `msg`
```
enc(k_msg, msg) -> cipher
```

3. For each recipient `i`:

  - 1. Generate recipient specific ephemeral keypar

  ```
  ephemeral key pair -> (ek_i_pri, ek_i_pub)
  ```

  - 2. Derive a shared secred with recipients long-term public key
  ```
  dh(ek_i_pri, pk_i) -> ss_i 
  ```

  - 3. Wrap the message key k_msg with the shared secret
  ```
  wrap(k_msg, ss_i) -> WrappedKey_i 
  ```

  - 4. Prepaire payload
  ```
  -> (ek_i_pub, WrappedKey_i, cipher)
  ```

4. Send each recpipient their payload


**Recipient i**
1. recieve tuple 
```
(ek_i_pub, WrappedKey_i, cipher)
```
2. derive shared secret using long term private key
```
dh(sk_i, ek_i_pub) -> ss_i 
```
3. Unwrap the message key
```
unwrap(WrappedKey_i, ss_i) -> k_msg 
```
4. Decrypt the message
```
dec(k_msg, cipher) -> msg 
```

**Properties**
- Forward secrecy
  - each recipients eph key is destroyed after use, thus compromise of the long-term private key of the sender does not expose past messages
- multi recipient
  - each recipient gets a unique eph key + wrapped key, thus the message ciphertext is only encrypted once
- no meta leak compromise
  - only the fact thtat the same message was sent to multiple recipients might be inferred - keys remain secure
