use openssl::error::ErrorStack;

mod utils;
use utils::ecies::ec_keypair;
use utils::ecies::ecies_decrypt;
use utils::ecies::ecies_encrypt;

fn main() -> Result<(), ErrorStack> {

    let (rec_pri, rec_pub) = ec_keypair()?;
    let rec_pri_pem = String::from_utf8(rec_pri.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let rec_pub_pem = String::from_utf8(rec_pub.public_key_to_pem().unwrap()).unwrap();

    let plaintext = b"Datex-ecies";
    let aad = b"context/AA";

    let msg = ecies_encrypt(&rec_pub_pem, plaintext, Some(aad))?;

    let pt = ecies_decrypt(&rec_pri_pem, &msg, Some(aad))?;

    assert_eq!(&pt, plaintext);
    println!("{:?}", String::from_utf8(pt));
    Ok(())
}
