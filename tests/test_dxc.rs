use datex_crypt::utils::datex_crypt::CryptoNative;
use datex_crypt::utils::datex_crypt::{
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    derive_x25519,
    hkdf
};
use datex_crypt::utils::crypto::CryptoTrait;

#[tokio::test]
async fn dsa_ed2519() {
    static CRYPTO: CryptoNative = CryptoNative {};
    let data = b"Some message to sign".to_vec();
    let fake_data = b"Some other message to sign".to_vec();

    let (pub_key, pri_key) = CRYPTO.gen_ed25519().await.unwrap();

    let sig: [u8; 64] = CRYPTO.sig_ed25519(&pri_key, &data).await.unwrap().try_into().unwrap();
    let fake_sig = [0u8; 64];

    assert_eq!(pub_key.len(), 32);
    assert_eq!(pri_key.len(), 32);
    assert_eq!(sig.len(), 64);

    assert!(CRYPTO.ver_ed25519(&pub_key, &sig, &data).await.unwrap());
    assert!(!CRYPTO.ver_ed25519(&pub_key, &sig, &fake_data).await.unwrap());
    assert!(!CRYPTO.ver_ed25519(&pub_key, &fake_sig, &data).await.unwrap());
}

#[test]
fn dh_x25519() {
    static CRYPTO: CryptoNative = CryptoNative {};
    let (ser_pub, ser_pri) = CRYPTO.gen_x25519().unwrap();
    let (cli_pub, cli_pri) = CRYPTO.gen_x25519().unwrap();

    let cli_shared = derive_x25519(&cli_pri, &ser_pub).unwrap();
    let ser_shared = derive_x25519(&ser_pri, &cli_pub).unwrap();

    assert_eq!(cli_shared, ser_shared);
    assert_eq!(cli_shared.len(), 32);
}

#[test]
fn test_hkdf() {
    const INFO: &[u8] = b"ECIES|X25519|HKDF-SHA256|AES-256-GCM";
    let ikm = vec![0u8; 32];
    let salt = vec![0u8; 16];

    let hash = hkdf(&ikm, &salt, &INFO, 32).unwrap();

    assert_eq!(hash.len(), 32);
}

#[test]
fn aes_gcm_roundtrip() {
    const INFO: &[u8] = b"ECIES|X25519|HKDF-SHA256|AES-256-GCM";
    let key = [0u8; 32];
    let iv = [0u8; 12];

    let data = b"Some message to encrypt".to_vec();

    let (ciphered, tag) = aes_gcm_encrypt(&key, &iv, &INFO, &data).unwrap();
    let deciphered = aes_gcm_decrypt(&key, &iv, &INFO, &ciphered, &tag).unwrap();

    assert_ne!(ciphered, data);
    assert_eq!(data, deciphered.to_vec());
}

#[test]
fn ecies_roundtrip() {
    static CRYPTO: CryptoNative = CryptoNative {};
    const INFO: &[u8] = b"ECIES|X25519|HKDF-SHA256|AES-256-GCM";
    let data = b"Some message to encrypt".to_vec();
    let (rec_pub_key, rec_pri_key) = CRYPTO.gen_x25519().unwrap();
    let ciphered = CRYPTO.ecies_encrypt(&rec_pub_key, &data, INFO).unwrap();
    let deciphered = CRYPTO.ecies_decrypt(&rec_pri_key, &ciphered, INFO).unwrap();

    assert_eq!(data, deciphered);
}
