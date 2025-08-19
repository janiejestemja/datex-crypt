use openssl::{error::ErrorStack, pkey::PKey};

mod utils;
use utils::ecies::ec_keypair;
use utils::ecies::ecies_decrypt;
use utils::ecies::ecies_encrypt;

fn encryption_logic() -> Result<(), ErrorStack> {
    let (rec_pri, rec_pub) = ec_keypair()?;
    let rec_pri_pem = String::from_utf8(rec_pri.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let rec_pub_pem = String::from_utf8(rec_pub.public_key_to_pem().unwrap()).unwrap();

    let plaintext = b"Datex-ecies";
    let aad = b"context";

    let msg = ecies_encrypt(&rec_pub_pem, plaintext, Some(aad))?;

    let pt = ecies_decrypt(&rec_pri_pem, &msg, Some(aad))?;

    assert_eq!(&pt, plaintext);
    println!("{:?}", String::from_utf8(pt));

    Ok(())
}

fn ecdsa_logic() -> Result<(), ErrorStack> {
    let data = b"Hello world!";
    let server_pkey = utils::ecdsa::gen_keypair().unwrap();
    let server_pub_pem = server_pkey.public_key_to_pem()?;
    let server_pub_key = PKey::public_key_from_pem(&server_pub_pem);

    let sig = utils::ecdsa::sign(&server_pkey, data).unwrap();
    let verified = utils::ecdsa::verify(&server_pub_key.unwrap(), data, &sig);

    println!("{:?}", verified);

    Ok(())
}

fn eddsa_logic() -> Result<bool, ErrorStack> {
    let data = b"Some message to sign".to_vec();
    let (pub_key, sig) = utils::ecdsa::gen_sig_ed25519(&data).unwrap();

    Ok(utils::ecdsa::ver_sig_ed25519(pub_key, sig, data).unwrap())
}

fn main() -> Result<(), ErrorStack> {
    encryption_logic()?;
    ecdsa_logic()?;
    eddsa_logic()?;
    Ok(())
}
