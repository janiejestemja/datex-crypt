use datex_crypt::crypto::crypto::CryptoTrait;
use datex_crypt::crypto::crypto_native::Crypt;

fn main() {
    let kek_bytes = [1u8; 32];
    let (arand, sym_key) = Crypt::key_upwrap(&kek_bytes)
        .unwrap();
    let brand = Crypt::key_unwrap(&kek_bytes, &arand)
        .unwrap();

    println!("{:?}", arand.len());
    println!("{:?}", brand.len());
}
