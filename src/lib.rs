#[cfg(feature = "c_api")]
mod c_api;

mod pk_signature;
mod pke;
mod ske;
mod traits;
use std::string::FromUtf8Error;

use aes_gcm::aead::OsRng;

#[cfg(feature = "c_api")]
pub use c_api::*;

pub use pk_signature::*;
pub use pke::*;
use sha2::{Digest, Sha256};
pub use ske::*;
pub use traits::{HexString, PemString};

use hex;
use rsa::{
    pkcs8,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    rand_core::{RngCore, SeedableRng},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
//use serde_json;
use rand_chacha::ChaCha20Rng;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SommelierDriveCryptoError {
    #[error("Invalid authorization seed length: given `{0}`, expected: 32.")]
    InvalidAuthorizationSeedLength(usize),
    #[error(transparent)]
    SkeError(#[from] SkeError),
    #[error(transparent)]
    PkeError(#[from] PkeError),
    #[error(transparent)]
    SignError(#[from] SignError),
    #[error(transparent)]
    Utf8Error(#[from] FromUtf8Error),
    #[error(transparent)]
    HexError(#[from] hex::FromHexError),
    #[error(transparent)]
    Pkcs8Error(#[from] pkcs8::Error),
    #[error(transparent)]
    Pkcs8SpkiError(#[from] pkcs8::spki::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PkeSecretKey(RsaPrivateKey);

impl PemString for PkeSecretKey {
    fn from_str(value: &str) -> Result<Self, SommelierDriveCryptoError> {
        let sk = RsaPrivateKey::from_pkcs8_pem(value)?;
        Ok(Self(sk))
    }

    fn to_string(&self) -> Result<String, SommelierDriveCryptoError> {
        let pem = self.0.to_pkcs8_pem(LineEnding::default())?;
        Ok(pem.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PkePublicKey(RsaPublicKey);

impl PemString for PkePublicKey {
    fn from_str(value: &str) -> Result<Self, SommelierDriveCryptoError> {
        let pk = RsaPublicKey::from_public_key_pem(value)?;
        Ok(Self(pk))
    }

    fn to_string(&self) -> Result<String, SommelierDriveCryptoError> {
        let pem = self.0.to_public_key_pem(LineEnding::default())?;
        Ok(pem.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymmetricKey(Vec<u8>);

impl HexString for SymmetricKey {
    fn from_str(value: &str) -> Result<Self, SommelierDriveCryptoError> {
        let bytes = hex::decode(value)?;
        Ok(Self(bytes))
    }

    fn to_string(&self) -> String {
        hex::encode(&self.0)
    }
}

impl SymmetricKey {
    pub const BYTE_SIZE: usize = 16;
}

pub type AuthorizationSeed = <ChaCha20Rng as SeedableRng>::Seed;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileCT {
    pub shared_key_cts: Vec<Vec<u8>>,
    pub filepath_cts: Vec<FilePathCT>,
    pub shared_key_hash: HashDigest,
    pub contents_ct: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadPermissionCT {
    pub shared_key_ct: Vec<u8>,
    pub filepath_ct: FilePathCT,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveredSharedKey {
    pub shared_key: SymmetricKey,
    pub shared_key_hash: HashDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationSeedCT(Vec<u8>);

impl HexString for AuthorizationSeedCT {
    fn from_str(value: &str) -> Result<Self, SommelierDriveCryptoError> {
        let bytes = hex::decode(value)?;
        Ok(Self(bytes))
    }

    fn to_string(&self) -> String {
        hex::encode(&self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilePathCT(Vec<u8>);

impl HexString for FilePathCT {
    fn from_str(value: &str) -> Result<Self, SommelierDriveCryptoError> {
        let bytes = hex::decode(value)?;
        Ok(Self(bytes))
    }

    fn to_string(&self) -> String {
        hex::encode(&self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashDigest(Vec<u8>);

impl TryFrom<&str> for HashDigest {
    type Error = SommelierDriveCryptoError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        Ok(Self(bytes))
    }
}

impl HexString for HashDigest {
    fn from_str(value: &str) -> Result<Self, SommelierDriveCryptoError> {
        let bytes = hex::decode(value)?;
        Ok(Self(bytes))
    }

    fn to_string(&self) -> String {
        hex::encode(&self.0)
    }
}

impl HashDigest {
    pub const SIZE: usize = 32;
    fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

pub fn encrypt_new_file(
    pks: &[PkePublicKey],
    filepath: &str,
    contents_bytes: &[u8],
) -> Result<FileCT, SommelierDriveCryptoError> {
    let (filepath_cts, shared_key_cts, recovered_shared_key) =
        encrypt_new_path_for_multi_pks(pks, filepath)?;
    let contents_ct = encrypt_new_file_with_shared_key(&recovered_shared_key, contents_bytes)?;
    let shared_key_hash = recovered_shared_key.shared_key_hash;

    Ok(FileCT {
        shared_key_cts,
        filepath_cts,
        shared_key_hash,
        contents_ct,
    })
}

pub fn encrypt_new_path_for_multi_pks(
    pks: &[PkePublicKey],
    filepath: &str,
) -> Result<(Vec<FilePathCT>, Vec<Vec<u8>>, RecoveredSharedKey), SommelierDriveCryptoError> {
    let mut rng = OsRng;
    let shared_key = ske_gen_key(&mut rng);
    let shared_key_hash = HashDigest::from_bytes(&Sha256::digest(&shared_key.0));
    let mut shared_key_cts = Vec::new();
    let mut filepath_cts = Vec::new();
    for pk in pks.into_iter() {
        let shared_key_ct = pke_encrypt(pk, &shared_key.0, &mut rng)?;
        let filepath_ct = encrypt_filepath(pk, filepath)?;
        shared_key_cts.push(shared_key_ct);
        filepath_cts.push(filepath_ct);
    }
    let recovered_shared_key = RecoveredSharedKey {
        shared_key,
        shared_key_hash,
    };
    Ok((filepath_cts, shared_key_cts, recovered_shared_key))
}

pub fn recover_shared_key(
    sk: &PkeSecretKey,
    ct: &[u8],
) -> Result<RecoveredSharedKey, SommelierDriveCryptoError> {
    let pke_plaintext = pke_decrypt(sk, &ct)?;
    let shared_key = SymmetricKey(pke_plaintext.to_vec());
    let shared_key_hash = HashDigest::from_bytes(&Sha256::digest(&shared_key.0));
    Ok(RecoveredSharedKey {
        shared_key,
        shared_key_hash,
    })
}

pub fn decrypt_contents_ct(
    recovered_shared_key: &RecoveredSharedKey,
    ct: &[u8],
) -> Result<Vec<u8>, SommelierDriveCryptoError> {
    let plaintext = ske_decrypt(&recovered_shared_key.shared_key, ct)?;
    Ok(plaintext)
}

pub fn encrypt_new_file_with_shared_key(
    recovered_shared_key: &RecoveredSharedKey,
    contents_bytes: &[u8],
) -> Result<Vec<u8>, SommelierDriveCryptoError> {
    let mut rng = OsRng;
    let mut nonce = [0; NONCE_BYTES_SIZE];
    rng.fill_bytes(&mut nonce);
    let contents_ct = ske_encrypt(&recovered_shared_key.shared_key, &nonce, contents_bytes)?;
    Ok(contents_ct)
}

pub fn gen_read_permission_ct(
    pk: &PkePublicKey,
    recovered_shared_key: &RecoveredSharedKey,
    filepath: &str,
) -> Result<ReadPermissionCT, SommelierDriveCryptoError> {
    let mut rng = OsRng;
    let shared_key_ct = pke_encrypt(pk, &recovered_shared_key.shared_key.0, &mut rng)?;
    let filepath_ct = encrypt_filepath(pk, filepath)?;
    let shared_key_ct = ReadPermissionCT {
        shared_key_ct,
        filepath_ct,
    };
    Ok(shared_key_ct)
}

pub fn gen_authorization_seed() -> AuthorizationSeed {
    let mut rng = OsRng;
    let mut authorization_seed = [0; 32];
    rng.fill_bytes(&mut authorization_seed);
    authorization_seed
}

pub fn encrypt_authorization_seed(
    pk: &PkePublicKey,
    authorization_seed: AuthorizationSeed,
) -> Result<AuthorizationSeedCT, SommelierDriveCryptoError> {
    let mut rng = OsRng;
    let ct = pke_encrypt(pk, &authorization_seed, &mut rng)?;
    Ok(AuthorizationSeedCT(ct))
}

pub fn decrypt_authorization_seed_ct(
    sk: &PkeSecretKey,
    authorization_seed_ct: &AuthorizationSeedCT,
) -> Result<AuthorizationSeed, SommelierDriveCryptoError> {
    let authorization_seed = pke_decrypt(sk, &authorization_seed_ct.0)?;
    Ok(authorization_seed.try_into().unwrap())
}

pub fn encrypt_filepath(
    pk: &PkePublicKey,
    filepath: &str,
) -> Result<FilePathCT, SommelierDriveCryptoError> {
    let mut rng = OsRng;
    let ct = pke_encrypt(pk, filepath.as_bytes(), &mut rng)?;
    let ct = FilePathCT(ct);
    Ok(ct)
}

pub fn decrypt_filepath_ct(
    sk: &PkeSecretKey,
    ct: &FilePathCT,
) -> Result<String, SommelierDriveCryptoError> {
    let plaintext = pke_decrypt(sk, &ct.0)?;
    let filepath = String::from_utf8(plaintext)?;
    Ok(filepath)
}

pub fn compute_permission_hash(user_id: u64, parent_filepath: &str) -> HashDigest {
    let mut hasher = Sha256::new();
    hasher.update(user_id.to_be_bytes());
    hasher.update(parent_filepath.as_bytes());
    HashDigest(hasher.finalize().to_vec().try_into().unwrap())
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
        let ct = encrypt_new_file(&pks, filepath, text).unwrap();

        let recovered_shared_key = recover_shared_key(&sks[0], &ct.shared_key_cts[0]).unwrap();
        let contents = decrypt_contents_ct(&recovered_shared_key, &ct.contents_ct).unwrap();
        assert_eq!(text, contents);
    }

    #[test]
    fn encrypt_new_file_with_shared_key_test() {
        let mut rng = OsRng;
        let sk = pke_gen_secret_key(&mut rng).unwrap();
        let pk = pke_gen_public_key(&sk);

        let filepath = "/test/filepath_test/test.txt";
        let text = "Hello, World!".as_bytes();
        let ct = encrypt_new_file(&vec![pk], filepath, text).unwrap();

        let recovered_shared_key = recover_shared_key(&sk, &ct.shared_key_cts[0]).unwrap();

        let new_text = "Hello, World?".as_bytes();
        let new_ct = encrypt_new_file_with_shared_key(&recovered_shared_key, new_text).unwrap();
        let contents = decrypt_contents_ct(&recovered_shared_key, &new_ct).unwrap();
        assert_eq!(contents, new_text);
        assert_ne!(contents, text);
    }

    #[test]
    fn read_permission_test() {
        let mut rng = OsRng;
        let sk = pke_gen_secret_key(&mut rng).unwrap();
        let pk = pke_gen_public_key(&sk);

        let filepath = "/test/filepath_test/test.txt";
        let text = "Hello, World!".as_bytes();
        let ct = encrypt_new_file(&vec![pk], filepath, text).unwrap();

        let recovered_shared_key = recover_shared_key(&sk, &ct.shared_key_cts[0]).unwrap();

        let new_sk = pke_gen_secret_key(&mut rng).unwrap();
        let new_pk = pke_gen_public_key(&new_sk);
        let new_permission =
            gen_read_permission_ct(&new_pk, &recovered_shared_key, filepath).unwrap();
        let recovered_shared_key =
            recover_shared_key(&new_sk, &new_permission.shared_key_ct).unwrap();
        let contents = decrypt_contents_ct(&recovered_shared_key, &ct.contents_ct).unwrap();
        assert_eq!(text, contents);
        let recovered_filepath = decrypt_filepath_ct(&new_sk, &new_permission.filepath_ct).unwrap();
        assert_eq!(filepath, &recovered_filepath);
    }

    #[test]
    fn authorization_seed_test() {
        let mut rng = OsRng;
        let sk = pke_gen_secret_key(&mut rng).unwrap();
        let pk = pke_gen_public_key(&sk);

        let authorization_seed = gen_authorization_seed();
        let derived_sk = pke_derive_secret_key_from_seeed(authorization_seed.clone()).unwrap();
        let ct = encrypt_authorization_seed(&pk, authorization_seed.clone()).unwrap();
        let recovered_seed = decrypt_authorization_seed_ct(&sk, &ct).unwrap();
        let recovered_sk = pke_derive_secret_key_from_seeed(recovered_seed.clone()).unwrap();
        assert_eq!(authorization_seed, recovered_seed);
        assert_eq!(derived_sk, recovered_sk);
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
        let nonce = 1;
        let fields = vec!["dataPK", "keywordPK"];
        let vals = vec!["pkd---", "pkw---"];
        let mut field_vals = BTreeMap::new();
        for (field, val) in fields.into_iter().zip(vals) {
            field_vals.insert(field, val);
        }
        let signature = gen_signature(&sk, region_name, method, uri, nonce, field_vals, &mut rng);

        let fields = vec!["keywordPK", "dataPK"];
        let vals = vec!["pkw---", "pkd---"];
        let mut field_vals = BTreeMap::new();
        for (field, val) in fields.into_iter().zip(vals).rev() {
            field_vals.insert(field, val);
        }
        let verified =
            verify_signature(&pk, region_name, method, uri, nonce, field_vals, &signature).unwrap();
        assert!(verified);
    }

    #[test]
    fn large_file_case_test() {
        let mut rng = OsRng;
        let num_key = 1;
        let sks = (0..num_key)
            .map(|_| pke_gen_secret_key(&mut rng).unwrap())
            .collect::<Vec<PkeSecretKey>>();
        let pks = sks
            .iter()
            .map(|sk| pke_gen_public_key(sk))
            .collect::<Vec<PkePublicKey>>();
        let filepath = "a".to_string().repeat(64);
        let text = [1; 1048576 * 2];
        let ct = encrypt_new_file(&pks, &filepath, &text).unwrap();
        let recovered_shared_key = recover_shared_key(&sks[0], &ct.shared_key_cts[0]).unwrap();
        let contents = decrypt_contents_ct(&recovered_shared_key, &ct.contents_ct).unwrap();
        assert_eq!(text.to_vec(), contents);
    }

    #[test]
    fn compute_permission_hash_test() {
        let user_id_1 = 1;
        let user_id_2 = 2;
        let parent_filepath = "/test/filepath_test";

        let hash1 = compute_permission_hash(user_id_1, parent_filepath);
        let hash2 = compute_permission_hash(user_id_2, parent_filepath);
        assert_ne!(hash1, hash2);
    }
}
