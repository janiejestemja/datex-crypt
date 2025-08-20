use openssl::{
    derive::Deriver,
    error::ErrorStack,
    pkey::{Id, PKey},
    pkey_ctx::{HkdfMode, PkeyCtx},
    md::Md,
    rand::rand_bytes,
    sign::{Signer, Verifier},
    symm::{Cipher, Crypter, Mode},
};

// HKDF
pub fn hkdf(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, ErrorStack> {
    let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_mode(HkdfMode::EXTRACT_THEN_EXPAND)?;
    ctx.set_hkdf_md(&Md::sha256())?;
    ctx.set_hkdf_salt(salt)?;
    ctx.set_hkdf_key(ikm)?;
    ctx.add_hkdf_info(info)?;
    let mut okm = vec![0u8; out_len];
    ctx.derive(Some(&mut okm))?;
    Ok(okm)
}

// XDH
pub fn gen_x25519() -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
    let key = PKey::generate_x25519()?;
    let public_key = key.raw_public_key()?;
    let private_key = key.raw_private_key()?;
    Ok((public_key, private_key))
}

pub fn derive_x25519(my_raw: &Vec<u8>, peer_pub: &Vec<u8>) -> Result<Vec<u8>, ErrorStack> {
    let peer_pub = PKey::public_key_from_raw_bytes(peer_pub, Id::X25519).unwrap();
    let my_priv = PKey::private_key_from_raw_bytes(my_raw, Id::X25519).unwrap();

    let mut deriver = Deriver::new(&my_priv)?;
    deriver.set_peer(&peer_pub)?;
    deriver.derive_to_vec()
}

// EdDSA
pub fn gen_ed25519() -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
    let key = PKey::generate_ed25519()?;
    let public_key = key.raw_public_key()?;
    let private_key = key.raw_private_key()?;
    Ok((public_key, private_key))
}

pub fn sig_ed25519(pri_key: &Vec<u8>, digest: &Vec<u8>) -> Result<Vec<u8>, ErrorStack> {
    let sig_key = PKey::private_key_from_raw_bytes(pri_key, Id::ED25519).unwrap();

    let mut signer = Signer::new_without_digest(&sig_key)?;
    let signature = signer.sign_oneshot_to_vec(digest)?;
    Ok(signature)
}

pub fn ver_ed25519(pub_key: &Vec<u8>, sig: &Vec<u8>, data: &Vec<u8>) -> Result<bool, ErrorStack> {
    let public_key = PKey::public_key_from_raw_bytes(&pub_key, Id::ED25519).unwrap();
    let mut verifier = Verifier::new_without_digest(&public_key).unwrap();
    Ok(verifier.verify_oneshot(&sig, &data).unwrap())
}

// AES GCM
pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const INFO: &[u8] = b"ECIES|X25519|HKDF-SHA256|AES-256-GCM";

pub fn aes_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), ErrorStack> {
    let cipher = Cipher::aes_256_gcm();
    let mut enc = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;
    enc.aad_update(aad)?;

    let mut out = vec![0u8; plaintext.len() + cipher.block_size()];
    let mut count = enc.update(plaintext, &mut out)?;
    count += enc.finalize(&mut out[count..])?;
    out.truncate(count);

    let mut tag = [0u8; TAG_LEN];
    enc.get_tag(&mut tag)?;
    Ok((out, tag))
}

pub fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_256_gcm();
    let mut dec = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
    dec.aad_update(aad)?;
    dec.set_tag(tag)?;

    let mut out = vec![0u8; ciphertext.len() + cipher.block_size()];
    let mut count = dec.update(ciphertext, &mut out)?;
    count += dec.finalize(&mut out[count..])?;
    out.truncate(count);
    Ok(out)
}

// ECIES
pub const SALT_LEN: usize = 16;

#[derive(Debug, Clone)]
pub struct Crypt {
    // Senders eph EC pub key (PEM)
    pub pub_key: Vec<u8>,
    // HKDF salt
    pub salt: [u8; SALT_LEN],
    // IV/nonce for AES-GCM
    pub iv: [u8; IV_LEN],
    // ciphertext
    pub ct: Vec<u8>,
    // AES-GCM tag (128-bit)
    pub tag: [u8; TAG_LEN],       
}
pub fn ecies_encrypt(
    rec_pub_raw: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Crypt, ErrorStack> {
    let (eph_pub, eph_pri) = gen_x25519()?;
    let shared = derive_x25519(&eph_pri, &rec_pub_raw.to_vec())?;

    // Map ikm to okm
    let mut salt = [0u8; 16];
    rand_bytes(&mut salt)?; // random salt?
    let key = hkdf(&shared, &salt, &INFO, 32).unwrap();

    // Nonce for AES
    let mut iv = [0u8; 12]; // 96-bit nonce?
    rand_bytes(&mut iv).unwrap();

    // Encrypt
    let (ct, tag) = aes_gcm_encrypt(
        &key,
        &iv,
        aad,
        plaintext,
    )?;

    Ok(Crypt {
        pub_key: eph_pub,
        salt: salt,
        iv: iv,
        ct: ct,
        tag: tag,
    })
}
// Recipient
pub fn ecies_decrypt(
    rec_pri_raw: &[u8],
    msg: &Crypt,
    aad: &[u8],
) -> Result<Vec<u8>, ErrorStack> {

    let shared = derive_x25519(&rec_pri_raw.to_vec(), &msg.pub_key)?;
    let key = hkdf(&shared, &msg.salt, &INFO, 32)?;

    aes_gcm_decrypt(&key, &msg.iv, aad, &msg.ct, &msg.tag)
}
