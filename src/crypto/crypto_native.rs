use super::crypto::{CryptoError, CryptoTrait};
use std::pin::Pin;

use openssl::{
    aes::{AesKey, unwrap_key, wrap_key},
    derive::Deriver,
    md::Md,
    pkey::{Id, PKey},
    pkey_ctx::{HkdfMode, PkeyCtx},
    rand::rand_bytes,
    sign::{Signer, Verifier},
    symm::{Cipher, Crypter, Mode},
};

pub struct Crypt {
    name: Vec<u8>,
}

impl Crypt {
    pub fn new(name: Vec<u8>) -> Crypt {
        Crypt { name }
    }
    pub fn name(&self) -> Vec<u8>{
        self.name.clone()
    }
}

impl CryptoTrait for Crypt {
    
    // EdDSA keygen
    fn gen_ed25519(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<u8>, Vec<u8>), CryptoError>> + 'static>>
    {
        Box::pin(async move {
            let key = PKey::generate_ed25519().map_err(|_| CryptoError::KeyGeneratorFailed)?;

            let public_key: Vec<u8> = key
                .public_key_to_der()
                .map_err(|_| CryptoError::KeyGeneratorFailed)?
                .try_into()
                .map_err(|_| CryptoError::KeyGeneratorFailed)?;
            let private_key: Vec<u8>= key
                .private_key_to_pkcs8()
                .map_err(|_| CryptoError::KeyGeneratorFailed)?
                .try_into()
                .map_err(|_| CryptoError::KeyGeneratorFailed)?;
            Ok((public_key, private_key))
        })
    }

    // EdDSA signature
    fn sig_ed25519<'a>(
        &self,
        pri_key: &'a Vec<u8>,
        digest: &'a Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, CryptoError>> + 'a>> {
        Box::pin(async move {
            let sig_key = PKey::private_key_from_pkcs8(pri_key)
                .map_err(|_| CryptoError::KeyImportFailed)?;
            let mut signer =
                Signer::new_without_digest(&sig_key).map_err(|_| CryptoError::SigningError)?;
            let signature = signer
                .sign_oneshot_to_vec(digest)
                .map_err(|_| CryptoError::SigningError)?;
            Ok(signature)
        })
    }

    // EdDSA verification of signature
    fn ver_ed25519<'a>(
        &self,
        pub_key: &'a Vec<u8>,
        sig: &'a [u8; 64],
        data: &'a Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, CryptoError>> + 'a>> {
        Box::pin(async move {
            let public_key = PKey::public_key_from_der(pub_key)
                .map_err(|_| CryptoError::KeyImportFailed)?;
            let mut verifier = Verifier::new_without_digest(&public_key)
                .map_err(|_| CryptoError::KeyImportFailed)?;
            Ok(verifier
                .verify_oneshot(sig, &data)
                .map_err(|_| CryptoError::VerificationError)?)
        })
    }

    // HKDF (hash)
    fn hkdf(ikm: &[u8], salt: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut ctx = PkeyCtx::new_id(Id::HKDF).map_err(|_| CryptoError::KeyDerivationFailed)?;
        ctx.derive_init()
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        ctx.set_hkdf_mode(HkdfMode::EXTRACT_THEN_EXPAND)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        ctx.set_hkdf_md(&Md::sha256())
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        ctx.set_hkdf_salt(salt)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        ctx.set_hkdf_key(ikm)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        /*
        ctx.add_hkdf_info(info)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        */
        let mut okm = vec![0u8; 32];
        ctx.derive(Some(&mut okm))
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        Ok(okm)
    }

    // AES CTR
    fn aes_ctr_encrypt(
        key: &[u8; 32],
        iv: &[u8; 16],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = Cipher::aes_256_ctr();
        let mut enc = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))
            .map_err(|_| CryptoError::EncryptionError)?;

        let mut out = vec![0u8; plaintext.len()];
        let count = enc
            .update(plaintext, &mut out)
            .map_err(|_| CryptoError::EncryptionError)?;
        out.truncate(count);
        Ok(out)
    }

    // Generate encryption keypair
    fn gen_x25519() -> Result<([u8; 32], [u8; 32]), CryptoError> {
        let key = PKey::generate_x25519().map_err(|_| CryptoError::KeyGeneratorFailed)?;
        let public_key: [u8; 32] = key
            .raw_public_key()
            .map_err(|_| CryptoError::KeyGeneratorFailed)?
            .try_into()
            .map_err(|_| CryptoError::KeyGeneratorFailed)?;
        let private_key: [u8; 32] = key
            .raw_private_key()
            .map_err(|_| CryptoError::KeyGeneratorFailed)?
            .try_into()
            .map_err(|_| CryptoError::KeyGeneratorFailed)?;
        Ok((private_key, public_key))
    }

    // Derive shared secret on x255109
    fn derive_x25519(
        my_raw: &[u8; 32],
        peer_pub: &[u8; 32],
    ) -> Result<Vec<u8>, CryptoError> {
        let peer_pub = PKey::public_key_from_raw_bytes(peer_pub, Id::X25519)
            .map_err(|_| CryptoError::KeyImportFailed)?;
        let my_priv = PKey::private_key_from_raw_bytes(my_raw, Id::X25519)
            .map_err(|_| CryptoError::KeyImportFailed)?;

        let mut deriver = Deriver::new(&my_priv).map_err(|_| CryptoError::KeyDerivationFailed)?;
        deriver
            .set_peer(&peer_pub)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        deriver
            .derive_to_vec()
            .map_err(|_| CryptoError::KeyDerivationFailed)
    }

    fn sym_key_gen() -> Result<[u8; 32], CryptoError> {
        // Random key
        let mut rb = [0u8; 32];
        rand_bytes(&mut rb).map_err(|_| CryptoError::KeyDerivationFailed)?;
        Ok(rb)
    }

    fn key_upwrap(
        kek_bytes: &[u8; 32],
        rb: &[u8; 32],
    ) -> Result<[u8; 40], CryptoError> {
        // Key encryption key
        let kek = AesKey::new_encrypt(kek_bytes).unwrap();

        // IV
        let iv = [0u8; 8];

        // Key wrap
        let mut wrapped = [0u8; 40];
        let _length = wrap_key(&kek, None, &mut wrapped, rb);

        Ok(wrapped)
    }

    fn key_unwrap(
        kek_bytes: &[u8; 32],
        cipher: &[u8; 40],
    ) -> Result<[u8; 32], CryptoError> {
        // Key encryption key
        let kek = AesKey::new_decrypt(kek_bytes).unwrap();

        // IV
        let iv = [0u8; 8];

        // Unwrap key 
        let mut unwrapped: [u8; 32] = [0u8; 32];
        let _length = unwrap_key(&kek, None, &mut unwrapped, cipher);

        Ok(unwrapped)
    }
}
