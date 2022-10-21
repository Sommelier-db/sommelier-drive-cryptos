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
    shared_key_ct: Vec<u8>,
    filepath_ct: FilePathCT,
    shared_key_hash: Vec<u8>,
    contents_ct: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCT {
    shared_key_ct: Vec<u8>,
    filepath_ct: FilePathCT,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredSharedKey {
    shared_key: SymmetricKey,
    shared_key_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePathCT {
    ct: Vec<u8>,
}

pub fn encrypt_new_file(
    pks: &[PkePublicKey],
    filepath: &str,
    contents_bytes: &[u8],
) -> Result<Vec<FileCT>, SommelierDriveCryptoError> {
    let mut rng = OsRng;
    let shared_key = ske_gen_key(&mut rng);
    let contents_ct = ske_encrypt(&shared_key, [0; 12], contents_bytes)?;
    let shared_key_hash = Sha256::digest(&shared_key.0).to_vec();

    let mut file_cts = Vec::new();
    for pk in pks.into_iter() {
        let shared_key_ct = pke_encrypt(pk, &shared_key.0, &mut rng)?;
        let filepath_ct = encrypt_filepath(pk, filepath)?;
        let file_ct = FileCT {
            shared_key_ct,
            filepath_ct,
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
    let shared_key = SymmetricKey(pke_plaintext.to_vec());
    let shared_key_hash = Sha256::digest(&shared_key.0).to_vec();
    Ok(RecoveredSharedKey {
        shared_key,
        shared_key_hash,
    })
}

pub fn decrypt_contents_ct(
    shared_key: &RecoveredSharedKey,
    ct: &[u8],
) -> Result<Vec<u8>, SommelierDriveCryptoError> {
    let plaintext = ske_decrypt(&shared_key.shared_key, [0; 12], ct)?;
    Ok(plaintext)
}

pub fn add_permission(
    pk: &PkePublicKey,
    recovered_shared_key: &RecoveredSharedKey,
    filepath: &str,
) -> Result<PermissionCT, SommelierDriveCryptoError> {
    let mut rng = OsRng;
    let shared_key_ct = pke_encrypt(pk, &recovered_shared_key.shared_key.0, &mut rng)?;
    let filepath_ct = encrypt_filepath(pk, filepath)?;
    let shared_key_ct = PermissionCT {
        shared_key_ct,
        filepath_ct,
    };
    Ok(shared_key_ct)
}

pub fn encrypt_filepath(
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

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn file_test() {
        let mut rng = OsRng;
        let num_key = 10;
        let sks = (0..num_key)
            .map(|_| pke_gen_secret_key(&mut rng).unwrap())
            .collect::<Vec<PkeSecretKey>>();
        let pks = sks
            .iter()
            .map(|sk| pke_gen_public_key(sk))
            .collect::<Vec<PkePublicKey>>();

        let filepath = "/test/filepath_test/test.txt";
        let text = "Hello, World!".as_bytes();
        let cts = encrypt_new_file(&pks, filepath, text).unwrap();

        let recovered_shared_key = recover_shared_key(&sks[0], &cts[0].shared_key_ct).unwrap();
        let contents = decrypt_contents_ct(&recovered_shared_key, &cts[0].contents_ct).unwrap();
        assert_eq!(text, contents);
    }

    #[test]
    fn permission_test() {
        let mut rng = OsRng;
        let sk = pke_gen_secret_key(&mut rng).unwrap();
        let pk = pke_gen_public_key(&sk);

        let filepath = "/test/filepath_test/test.txt";
        let text = "Hello, World!".as_bytes();
        let ct = encrypt_new_file(&vec![pk], filepath, text).unwrap()[0].clone();

        let recovered_shared_key = recover_shared_key(&sk, &ct.shared_key_ct).unwrap();

        let new_sk = pke_gen_secret_key(&mut rng).unwrap();
        let new_pk = pke_gen_public_key(&new_sk);
        let new_permission = add_permission(&new_pk, &recovered_shared_key, filepath).unwrap();
        let recovered_shared_key =
            recover_shared_key(&new_sk, &new_permission.shared_key_ct).unwrap();
        let contents = decrypt_contents_ct(&recovered_shared_key, &ct.contents_ct).unwrap();
        assert_eq!(text, contents);
        let recovered_filepath = decrypt_filepath_ct(&new_sk, &new_permission.filepath_ct).unwrap();
        assert_eq!(filepath, &recovered_filepath);
    }

    #[test]
    fn filepath_test() {
        let mut rng = OsRng;
        let sk = pke_gen_secret_key(&mut rng).unwrap();
        let pk = pke_gen_public_key(&sk);

        let filepath = "/test/filepath_test/test.txt";
        let ct = encrypt_filepath(&pk, filepath).unwrap();
        let decrypted_path = decrypt_filepath_ct(&sk, &ct).unwrap();
        assert_eq!(filepath, &decrypted_path);
    }

    #[test]
    fn sign_test() {
        let mut rng = OsRng;
        let sk = pke_gen_secret_key(&mut rng).unwrap();
        let pk = pke_gen_public_key(&sk);

        let region_name = "sign_test";
        let method = "POST";
        let uri = "/user";
        let fields = vec!["dataPK", "keywordPK"];
        let vals = vec!["pkd---", "pkw---"];
        let mut field_vals = BTreeMap::new();
        for (field, val) in fields.iter().zip(&vals) {
            field_vals.insert(field.to_string(), val.to_string());
        }
        let signature = gen_signature(&sk, region_name, method, uri, &field_vals, &mut rng);

        let mut field_vals = BTreeMap::new();
        for (field, val) in fields.iter().zip(&vals).rev() {
            field_vals.insert(field.to_string(), val.to_string());
        }
        let verified =
            verify_signature(&pk, region_name, method, uri, &field_vals, &signature).unwrap();
        assert!(verified);
    }
}
