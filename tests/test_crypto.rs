use datex_crypt::crypto::crypto::CryptoTrait;
use datex_crypt::crypto::crypto_native::Crypt;

#[tokio::test]
async fn dsa_ed2519() {
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
