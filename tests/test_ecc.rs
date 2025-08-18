use datex_crypt::utils::ecdsa::*;
use datex_crypt::utils::ecies::*;
use openssl::pkey::PKey;

#[test]
fn sign_verify() {
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
