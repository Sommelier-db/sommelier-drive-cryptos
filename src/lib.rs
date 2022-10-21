mod pk_signature;
mod pke;
mod ske;
use std::string::FromUtf8Error;

use aes_gcm::aead::OsRng;
pub use pk_signature::*;
pub use pke::*;
use sha2::{Digest, Sha256};
pub use ske::*;

use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkeSecretKey(RsaPrivateKey);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkePublicKey(RsaPublicKey);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymmetricKey(Vec<u8>);

#[derive(Error, Debug)]
pub enum SommelierDriveCryptoError {
    #[error(transparent)]
    SkeError(#[from] SkeError),
    #[error(transparent)]
    PkeError(#[from] PkeError),
    #[error(transparent)]
    SignError(#[from] SignError),
    #[error(transparent)]
    Utf8Error(#[from] FromUtf8Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCT {
    shared_key_ct: SharedKeyCT,
    shared_key_hash: Vec<u8>,
    contents_ct: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedKeyCT {
    shared_key_ct: Vec<u8>,
    filepath_ct: FilePathCT,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredSharedKey {
    shared_key: SymmetricKey,
    shared_key_hash: Vec<u8>,
    user_id: usize,
    nonce: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePathCT {
    ct: Vec<u8>,
}

pub fn encrypt_new_file(
    pks: &[PkePublicKey],
    region_name: &str,
    user_id: usize,
    nonce: usize,
    filepath: &str,
    contents_bytes: &[u8],
) -> Result<Vec<FileCT>, SommelierDriveCryptoError> {
    let mut rng = OsRng;
    let mut shared_key = ske_gen_key(&mut rng);
    let contents_ct = ske_encrypt(&shared_key, region_name, user_id, nonce, contents_bytes)?;
    let shared_key_hash = Sha256::digest(&shared_key.0).to_vec();

    let mut pke_plaintext = user_id.to_be_bytes().to_vec();
    pke_plaintext.append(&mut nonce.to_be_bytes().to_vec());
    pke_plaintext.append(&mut shared_key.0);

    let mut file_cts = Vec::new();
    for pk in pks.into_iter() {
        let shared_key_ct = pke_encrypt(pk, &pke_plaintext, &mut rng)?;
        let filepath_ct = encrypt_new_filepath(pk, filepath)?;
        let shared_key_ct = SharedKeyCT {
            shared_key_ct,
            filepath_ct,
        };
        let file_ct = FileCT {
            shared_key_ct,
            shared_key_hash: shared_key_hash.clone(),
            contents_ct: contents_ct.clone(),
        };
        file_cts.push(file_ct)
    }
    Ok(file_cts)
}

pub fn recover_shared_key(
    sk: &PkeSecretKey,
    ct: &[u8],
) -> Result<RecoveredSharedKey, SommelierDriveCryptoError> {
    let pke_plaintext = pke_decrypt(sk, &ct)?;
    let user_id = usize::from_be_bytes(pke_plaintext[0..8].try_into().unwrap());
    let nonce = usize::from_be_bytes(pke_plaintext[8..16].try_into().unwrap());
    let shared_key = SymmetricKey(pke_plaintext[16..].to_vec());
    let shared_key_hash = Sha256::digest(&shared_key.0).to_vec();
    Ok(RecoveredSharedKey {
        shared_key,
        shared_key_hash,
        user_id,
        nonce,
    })
}

pub fn add_permission(
    pk: &PkePublicKey,
    recovered_shared_key: &RecoveredSharedKey,
    filepath: &str,
) -> Result<SharedKeyCT, SommelierDriveCryptoError> {
    let mut rng = OsRng;
    let mut pke_plaintext = recovered_shared_key.user_id.to_be_bytes().to_vec();
    pke_plaintext.append(&mut recovered_shared_key.nonce.to_be_bytes().to_vec());
    pke_plaintext.append(&mut recovered_shared_key.shared_key.0.to_vec());
    let shared_key_ct = pke_encrypt(pk, &pke_plaintext, &mut rng)?;
    let filepath_ct = encrypt_new_filepath(pk, filepath)?;
    let shared_key_ct = SharedKeyCT {
        shared_key_ct,
        filepath_ct,
    };
    Ok(shared_key_ct)
}

pub fn encrypt_new_filepath(
    pk: &PkePublicKey,
    filepath: &str,
) -> Result<FilePathCT, SommelierDriveCryptoError> {
    let mut rng = OsRng;

    let ct = pke_encrypt(pk, filepath.as_bytes(), &mut rng)?;
    let ct = FilePathCT { ct };
    Ok(ct)
}

pub fn decrypt_filepath_ct(
    sk: &PkeSecretKey,
    ct: &FilePathCT,
) -> Result<String, SommelierDriveCryptoError> {
    let plaintext = pke_decrypt(sk, &ct.ct)?;
    let filepath = String::from_utf8(plaintext)?;
    Ok(filepath)
}
