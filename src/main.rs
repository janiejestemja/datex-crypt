use datex_crypt::crypto::crypto_native::Crypt;

fn main() {
    let crypta: Crypt = Crypt::new(b"RsCrypt".to_vec());
    println!("{:?}", crypta.name());
}
