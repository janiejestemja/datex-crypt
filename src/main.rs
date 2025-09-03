use datex_crypt::crypto::crypto::CryptoTrait;
use datex_crypt::crypto::crypto_native::Crypt;

fn main() {
    let arand = Crypt::encrypt_payload()
        .unwrap();
    let brand = Crypt::decrypt_payload(&arand)
        .unwrap();

    println!("{:?}", arand.len());
    println!("{:?}", brand.len());
}
