use std::pin::Pin;
use crate::utils::datex_crypt::{
    KEY_LEN,
    SIG_LEN,
    Crypt,
};

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
    fn gen_ed25519(&self) -> Pin<Box<dyn Future<Output = Result<([u8; KEY_LEN], [u8; KEY_LEN]), CryptoError>> + 'static>>;

    fn sig_ed25519<'a>(
        &'a self,
        pri_key: &'a [u8; KEY_LEN], 
        digest: &'a Vec<u8>
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, CryptoError>> + Send + 'a>>;

    fn ver_ed25519<'a>(
        &'a self,
        pub_key: &'a [u8; KEY_LEN],
        sig: &'a [u8; SIG_LEN],
        data: &'a Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, CryptoError>> + Send + 'a>>;

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
