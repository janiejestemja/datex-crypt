use openssl::{
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
    sign::{Signer, Verifier},
};

// ECDSA
pub fn gen_keypair() -> Result<PKey<Private>, ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::BRAINPOOL_P384R1)
        .expect("curve missing; consider using another");
    let ec = EcKey::generate(&group)?;
    Ok(PKey::from_ec_key(ec)?)
}

pub fn sign(privkey: &PKey<Private>, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let mut signer = Signer::new(MessageDigest::sha256(), privkey)?;
    signer.update(data)?;
    Ok(signer.sign_to_vec()?)
}

pub fn verify(pubkey: &PKey<Public>, data: &[u8], sign: &[u8]) -> Result<bool, ErrorStack> {
    let mut verifier = Verifier::new(MessageDigest::sha256(), pubkey)?;
    verifier.update(data)?;
    Ok(verifier.verify(sign)?)
}

pub fn gen_sig_ed25519(digest: &Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
    let key = PKey::generate_ed25519()?;
    let public_key = key.raw_public_key()?;

    let mut signer = Signer::new_without_digest(&key)?;
    let signature = signer.sign_oneshot_to_vec(digest)?;
    assert_eq!(signature.len(), 64);
    Ok((public_key, signature))
}

pub fn ver_sig_ed25519(pub_key: Vec<u8>, sig: Vec<u8>, data: Vec<u8>) -> Result<bool, ErrorStack> {
    let public_key = PKey::public_key_from_raw_bytes(&pub_key, Id::ED25519).unwrap();
    let mut verifier = Verifier::new_without_digest(&public_key).unwrap();
    Ok(verifier.verify_oneshot(&sig, &data).unwrap())
}
