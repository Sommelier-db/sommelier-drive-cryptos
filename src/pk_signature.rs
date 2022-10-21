use std::collections::BTreeMap;

use crate::{PkePublicKey, PkeSecretKey};
use aes_gcm::aead::rand_core::{CryptoRng, RngCore};
use rsa::pss;
use rsa::pss::{BlindedSigningKey, VerifyingKey};
use sha2::Sha256;
use signature::{RandomizedSigner, Signature, Verifier};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignError {
    #[error("Fail to decode a signature bytes")]
    SignatureBytesDecodingError,
}

pub fn sign<R: CryptoRng + RngCore>(
    sk: &PkeSecretKey,
    region_name: &str,
    method: &str,
    uri: &str,
    field_vals: &BTreeMap<String, String>,
    rng: &mut R,
) -> Vec<u8> {
    let signing_key = BlindedSigningKey::<Sha256>::new(sk.0.clone());
    let data = build_sign_data(region_name, method, uri, field_vals);
    let signature = signing_key.sign_with_rng(rng, &data);
    signature.as_bytes().to_vec()
}

pub fn verify(
    pk: &PkePublicKey,
    region_name: &str,
    method: &str,
    uri: &str,
    field_vals: &BTreeMap<String, String>,
    signature: &[u8],
) -> Result<bool, SignError> {
    let vk = VerifyingKey::<Sha256>::new(pk.0.clone());
    let data = build_sign_data(region_name, method, uri, field_vals);
    let signature = pss::Signature::from_bytes(signature)
        .map_err(|_| SignError::SignatureBytesDecodingError)?;
    let verified = vk.verify(&data, &signature);
    Ok(verified.is_ok())
}

fn build_sign_data(
    region_name: &str,
    method: &str,
    uri: &str,
    field_vals: &BTreeMap<String, String>,
) -> Vec<u8> {
    let mut data = region_name.as_bytes().to_vec();
    data.append(&mut method.as_bytes().to_vec());
    data.append(&mut uri.as_bytes().to_vec());
    for (field, val) in field_vals.into_iter() {
        let concated = format!("{}:{},", field, val);
        data.append(&mut concated.as_bytes().to_vec());
    }
    data
}
