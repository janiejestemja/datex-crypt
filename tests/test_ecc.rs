use datex_crypt::utils::datex_crypt::*;
use datex_crypt::utils::ecdsa::*;
use datex_crypt::utils::ecies::*;
use openssl::pkey::PKey;

#[test]
fn ecdsa_sign_verify() {
    let data = b"Hello world!";
    let fake_data = b"Goodbye world!";
    let server_pkey = gen_keypair().unwrap();
    let server_pub_pem = server_pkey.public_key_to_pem().unwrap();
    let server_pub_key = PKey::public_key_from_pem(&server_pub_pem);

    let sig = sign(&server_pkey, data).unwrap();
    let verified = verify(&server_pub_key.as_ref().unwrap(), data, &sig).unwrap();

    let unverified = verify(&server_pub_key.unwrap(), fake_data, &sig).unwrap();

    assert!(verified);
    assert!(!unverified);
}

#[test]
fn ecies_roundtrip() {
    let (rec_pri, rec_pub) = ec_keypair().unwrap();
    let rec_pri_pem = String::from_utf8(rec_pri.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let rec_pub_pem = String::from_utf8(rec_pub.public_key_to_pem().unwrap()).unwrap();

    let plaintext = b"Datex-ecies";
    let aad = b"context";

    let msg = ecies_encrypt(&rec_pub_pem, plaintext, Some(aad)).unwrap();

    let pt = ecies_decrypt(&rec_pri_pem, &msg, Some(aad)).unwrap();

    assert_ne!(msg.ct, plaintext);
    assert_eq!(&pt, plaintext);
}

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
}
