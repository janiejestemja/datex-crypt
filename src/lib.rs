use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;

use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};

use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
use openssl::sign::{Signer, Verifier};

// PKCS PBKDF2 HMAC
pub fn derive_key_iv(input_key_material: &[u8], salt: &[u8], iter: usize) -> (Vec<u8>, Vec<u8>) {
    let mut key = vec![0u8; 32]; // 256-bit key
    let mut iv = vec![0u8; 16]; // 128-bit IV

    pbkdf2_hmac(
        input_key_material,
        salt,
        iter,
        MessageDigest::sha256(),
        &mut key,
    )
    .unwrap();

    pbkdf2_hmac(
        input_key_material,
        salt,
        iter,
        MessageDigest::sha256(),
        &mut iv,
    )
    .unwrap();

    (key, iv)
}

// ECDH
pub fn server_generate_key() -> Result<(PKey<Private>, Vec<u8>), ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
    let key = EcKey::generate(&group)?;
    let server_key = key.clone();
    let server_pkey: PKey<_> = server_key.try_into()?;

    let mut ctx = BigNumContext::new()?;
    let shared_public =
        key.public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)?;

    let shared_public = shared_public.to_vec();

    Ok((server_pkey, shared_public))
}

pub fn client_derive_key(server_public: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
    let key = EcKey::generate(&group)?;
    let client_key = key.clone();

    let mut ctx = BigNumContext::new()?;
    let server_point = EcPoint::from_bytes(&group, server_public, &mut ctx)?;
    let server_pubkey = EcKey::from_public_key(&group, &server_point)?;
    let server_pkey: PKey<_> = server_pubkey.try_into()?;

    let client_pkey: PKey<_> = key.try_into()?;

    let client_public =
        client_key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)?;

    let mut deriver = Deriver::new(&client_pkey)?;
    deriver.set_peer(&server_pkey)?;
    let shared_secret = deriver.derive_to_vec()?;

    Ok((client_public, shared_secret))
}

pub fn server_derive_key(
    client_public: &[u8],
    server_pkey: &PKey<Private>,
) -> Result<Vec<u8>, ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
    let mut ctx = BigNumContext::new()?;

    let client_point = EcPoint::from_bytes(&group, client_public, &mut ctx)?;
    let client_pubkey = EcKey::from_public_key(&group, &client_point)?;
    let client_pkey: PKey<_> = client_pubkey.try_into()?;

    let mut deriver = Deriver::new(server_pkey)?;
    deriver.set_peer(&client_pkey)?;
    let shared_secret = deriver.derive_to_vec()?;

    Ok(shared_secret)
}

// AES 256 GCM
// returns: concat(nonce || ciphertext || tag)
pub fn ossl_aes_gcm_enc(key: &[u8; 32], nonce: &[u8; 16], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_256_gcm();

    // Alternative to nonce from pbkdf2
    // let mut nonce = [0u8; 12];
    // rand_priv_bytes(&mut nonce).unwrap();

    let mut tag = [0u8; 16];
    let ciphertext = encrypt_aead(cipher, key, Some(nonce), aad, plaintext, &mut tag)?;

    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

pub fn ossl_aes_gcm_dec(key: &[u8; 32], payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    // assert_eq!(payload.len(), 16 + 16);
    let (nonce, rest) = payload.split_at(16);
    let (ct, tag) = rest.split_at(rest.len() - 16);

    let plaintext = decrypt_aead(Cipher::aes_256_gcm(), key, Some(nonce), aad, ct, tag)?;
    Ok(plaintext)
}

// ECDSA
pub fn generate_ecdsa_keypair() -> Result<PKey<Private>, ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::BRAINPOOL_P384R1)
        .expect("curve missing; consider using another");
    let ec = EcKey::generate(&group)?;
    Ok(PKey::from_ec_key(ec)?)
}

pub fn sign_ecdsa(privkey: &PKey<Private>, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let mut signer = Signer::new(MessageDigest::sha256(), privkey)?;
    signer.update(data)?;
    Ok(signer.sign_to_vec()?)
}

pub fn verify_ecdsa(pubkey: &PKey<Public>, data: &[u8], sign: &[u8]) -> Result<(), ErrorStack> {
    let mut verifier = Verifier::new(MessageDigest::sha256(), pubkey)?;
    verifier.update(data)?;
    if verifier.verify(sign)? {
        Ok(())
    } else {
        panic!()
    }
}
