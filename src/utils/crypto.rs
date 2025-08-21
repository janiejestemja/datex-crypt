use crate::utils::datex_crypt::{
    KEY_LEN,
    SIG_LEN,
    Crypt,
};
use openssl::error::ErrorStack;

pub trait CryptoTrait {
    // ECIES
    fn gen_x25519(&self) -> Result<([u8; KEY_LEN], [u8; KEY_LEN]), CryptoError>;

    fn ecies_encrypt(
        &self,
        rec_pub_raw: &[u8; KEY_LEN],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Crypt, CryptoError>;

    fn ecies_decrypt(
        &self,
        rec_pri_raw: &[u8; KEY_LEN],
        msg: &Crypt,
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    // EdDSA
    fn gen_ed25519(&self) -> Result<([u8; KEY_LEN], [u8; KEY_LEN]), ErrorStack>;

    fn sig_ed25519(
        &self,
        pri_key: &[u8; KEY_LEN], 
        digest: &Vec<u8>
    ) -> Result<Vec<u8>, ErrorStack>;

    fn ver_ed25519(
        &self,
        pub_key: &[u8; KEY_LEN],
        sig: &[u8; SIG_LEN],
        data: &Vec<u8>,
    ) -> Result<bool, ErrorStack>;

}

#[derive(Debug, Clone)]
pub enum CryptoError {
    Other(String),
    KeyGeneratorFailed,
    KeyExportFailed,
    KeyImportFailed,
    KeyDerivationFailed,
    EncryptionError,
    DecryptionError,
    SigningError,
    VerificationError,
}
