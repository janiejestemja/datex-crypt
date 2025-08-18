use openssl::{
    derive::Deriver,
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    md::Md,
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
    pkey_ctx::{HkdfMode, PkeyCtx},
    rand::rand_bytes,
    symm::{Cipher, Crypter, Mode},
};

// Placeholder for stable binary encoding
#[derive(Debug, Clone)]
pub struct EciesMsg {
    pub eph_pub_pem: String, // Senders eph EC pub key (PEM)
    pub salt: Vec<u8>,       // HKDF salt
    pub iv: Vec<u8>,         // IV/nonce for AES-GCM
    pub ct: Vec<u8>,         // ciphertext
    pub tag: [u8; 16],       // AES-GCM tag (128-bit)
}

// HKDF
pub fn hkdf_sha256(
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

// AES GCM
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

    let mut tag = [0u8; 16];
    enc.get_tag(&mut tag)?;
    Ok((out, tag))
}

pub fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
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

// EC
pub fn ec_keypair() -> Result<(PKey<Private>, PKey<Public>), ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::BRAINPOOL_P384R1)?;
    let ec_key = EcKey::generate(&group)?;
    let pri_pkey = PKey::from_ec_key(ec_key)?;
    let pub_pkey = PKey::public_key_from_pem(&pri_pkey.public_key_to_pem()?)?;
    Ok((pri_pkey, pub_pkey))
}

// Derive
pub fn derive(my_priv: &PKey<Private>, peer_pub: &PKey<Public>) -> Result<Vec<u8>, ErrorStack> {
    let mut deriver = Deriver::new(my_priv)?;
    deriver.set_peer(peer_pub)?;
    deriver.derive_to_vec()
}

// ECIES
const INFO_STR: &[u8] = b"ECIES|P-384|HKDF-SHA256|AES-256-GCM";

// Sender
pub fn ecies_encrypt(
    recipient_pub_pem: &str,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<EciesMsg, ErrorStack> {
    let recipient_pub = PKey::public_key_from_pem(recipient_pub_pem.as_bytes()).unwrap();
    // Derive ikm
    let (eph_pri, eph_pub) = ec_keypair()?;
    let shared = derive(&eph_pri, &recipient_pub)?;

    // Map ikm to okm
    let mut salt = vec![0u8; 16];
    rand_bytes(&mut salt)?;
    let key = hkdf_sha256(&shared, &salt, INFO_STR, 32)?;

    // Encrypt
    let mut iv = vec![0u8; 12]; // 96-bit nonce?
    rand_bytes(&mut iv)?;
    let aad = aad.unwrap_or(b"");
    let (ct, tag) = aes_gcm_encrypt(&key, &iv, aad, plaintext)?;

    let eph_pub_pem = String::from_utf8(eph_pub.public_key_to_pem()?).expect("PEM is valid UTF-8");

    Ok(EciesMsg {
        eph_pub_pem,
        salt,
        iv,
        ct,
        tag,
    })
}

// Recipient
pub fn ecies_decrypt(
    recipient_priv_pem: &str,
    msg: &EciesMsg,
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, ErrorStack> {
    let recipient_priv = PKey::private_key_from_pem(recipient_priv_pem.as_bytes()).unwrap();
    let eph_pub = PKey::public_key_from_pem(&msg.eph_pub_pem.as_bytes()).unwrap();

    let shared = derive(&recipient_priv, &eph_pub)?;

    let key = hkdf_sha256(&shared, &msg.salt, INFO_STR, 32)?;

    let aad = aad.unwrap_or(b"");
    aes_gcm_decrypt(&key, &msg.iv, aad, &msg.ct, &msg.tag)
}
