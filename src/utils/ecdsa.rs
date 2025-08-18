use openssl::{
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
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
