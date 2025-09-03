use std::pin::Pin;

pub const PUB_KEY_LEN: usize = 48;
pub const PRI_KEY_LEN: usize = 44;
pub const SIG_LEN: usize = 64;

pub trait CryptoTrait {
    // EdDSA
    fn gen_ed25519(
    ) -> Pin<Box<dyn Future<Output = Result<([u8; PRI_KEY_LEN], [u8; PUB_KEY_LEN]), CryptoError>> + 'static>>;

    fn sig_ed25519<'a>(
        pri_key: &'a [u8; PRI_KEY_LEN],
        digest: &'a Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<[u8; 64], CryptoError>> + 'a>>;

    fn ver_ed25519<'a>(
        pub_key: &'a [u8; PUB_KEY_LEN],
        sig: &'a [u8; SIG_LEN],
        data: &'a Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, CryptoError>> + 'a>>;
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
