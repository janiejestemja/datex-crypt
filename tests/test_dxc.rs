use datex_crypt::utils::datex_crypt::*;

#[test]
fn eddsa_sign_verify() {
    let data = b"Some message to sign".to_vec();
    let (pub_key, pri_key) = gen_ed25519().unwrap();

    let sig = sig_ed25519(&pri_key, &data).unwrap();

    assert!(ver_ed25519(pub_key, sig, data).unwrap());
}

#[test]
fn dh_x25519() {
    let (ser_pub, ser_pri) = gen_x25519().unwrap();
    let (cli_pub, cli_pri) = gen_x25519().unwrap();

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
