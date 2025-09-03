use datex_crypt::crypto::crypto::CryptoTrait;
use datex_crypt::crypto::crypto_native::Crypt;

#[tokio::test]
async fn test_dsa_ed2519() {
    let crystruct: Crypt = Crypt::new(b"RsCipher".to_vec());
    let data = b"Some message to sign".to_vec();
    let fake_data = b"Some other message to sign".to_vec();

    let (pub_key, pri_key) = crystruct.gen_ed25519().await.unwrap();

    let sig: [u8; 64] = crystruct
        .sig_ed25519(&pri_key, &data)
        .await
        .unwrap()
        .try_into()
        .unwrap();
    let fake_sig = [0u8; 64];

    assert_eq!(sig.len(), 64);

    assert!(crystruct.ver_ed25519(&pub_key, &sig, &data).await.unwrap());
    assert!(
        !crystruct
            .ver_ed25519(&pub_key, &sig, &fake_data)
            .await
            .unwrap()
    );
    assert!(
        !crystruct
            .ver_ed25519(&pub_key, &fake_sig, &data)
            .await
            .unwrap()
    );
}

#[test]
fn aes_ctr_roundtrip() {
    let data = b"Some message to encrypt".to_vec();

    let ikm = [0u8; 16];
    let salt = [0u8; 16];
    let iv = [0u8; 16];

    let hash: [u8; 32] = Crypt::hkdf(&ikm, &salt)
        .unwrap()
        .try_into()
        .unwrap();

    let cipher = Crypt::aes_ctr_encrypt(&hash, &iv, &data).unwrap();
    let plain = Crypt::aes_ctr_encrypt(&hash, &iv, &cipher).unwrap();

    assert_ne!(data, cipher);
    assert_eq!(plain, data);
}

#[test]
fn test_dh_x25519() {
    let (ser_pub, ser_pri) = Crypt::gen_x25519().unwrap();
    let (cli_pub, cli_pri) = Crypt::gen_x25519().unwrap();

    let cli_shared = Crypt::derive_x25519(&cli_pri, &ser_pub).unwrap();
    let ser_shared = Crypt::derive_x25519(&ser_pri, &cli_pub).unwrap();

    assert_eq!(cli_shared, ser_shared);
    assert_eq!(cli_shared.len(), 32);
}

#[test]
fn test_keywrapping() {
    let kek_bytes = [1u8; 32];
    let (arand, sym_key) = Crypt::key_upwrap(&kek_bytes)
        .unwrap();
    let brand = Crypt::key_unwrap(&kek_bytes, &arand)
        .unwrap();

    assert_ne!(arand.to_vec(), brand.to_vec());
    assert_eq!(arand.len() , brand.len() + 8);
}

#[test]
fn test_roundtrip() {
    // Given
    let (cli_pub, cli_pri) = Crypt::gen_x25519().unwrap();

    // Sender (server)
    let (ser_pub, ser_pri) = Crypt::gen_x25519().unwrap();
    let ser_kek_bytes: [u8; 32] = Crypt::derive_x25519(&ser_pri, &cli_pub)
        .unwrap().try_into().unwrap();

    // Generate wrapped and symmetric random key
    let (arand, sym_key) = Crypt::key_upwrap(&ser_kek_bytes)
        .unwrap();

    // Encrypt data with symmetric key
    let data = b"Some message to encrypt".to_vec();
    let iv = [0u8; 16];
    let cipher = Crypt::aes_ctr_encrypt(&sym_key, &iv, &data).unwrap();


    // Receiver (client)
    // Unwraps key and decrypts
    let cli_kek_bytes: [u8; 32] = Crypt::derive_x25519(&cli_pri, &ser_pub)
        .unwrap().try_into().unwrap();
    let brand = Crypt::key_unwrap(&cli_kek_bytes, &arand)
        .unwrap();
    let plain = Crypt::aes_ctr_encrypt(&brand, &iv, &cipher).unwrap();

    // Check key wraps
    assert_ne!(arand.to_vec(), brand.to_vec());
    assert_eq!(arand.len() , brand.len() + 8);

    // Check data, cipher and deciphered
    assert_ne!(data, cipher);
    assert_eq!(plain, data);
}
