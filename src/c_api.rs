use crate::*;
use core::slice;
use easy_ffi::easy_ffi;
use hex;
use std::collections::BTreeMap;
use std::ffi::*;
use std::mem;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::ptr;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CFileCT {
    pub num_cts: usize,
    pub shared_key_cts: *mut CSharedKeyCT,
    pub filepath_cts: *mut CFilePathCT,
    pub shared_key_hash: *mut c_char,
    pub contents_ct: *mut c_char,
}

impl Default for CFileCT {
    fn default() -> Self {
        let shared_key_cts = ptr::null_mut();
        let filepath_cts = ptr::null_mut();
        Self {
            num_cts: 0,
            shared_key_cts,
            filepath_cts,
            shared_key_hash: str2ptr(String::new()),
            contents_ct: str2ptr(String::new()),
        }
    }
}

impl TryFrom<FileCT> for CFileCT {
    type Error = SommelierDriveCryptoError;
    fn try_from(value: FileCT) -> Result<Self, Self::Error> {
        let num_cts = value.shared_key_cts.len();
        let mut shared_key_cts_vec: Vec<CSharedKeyCT> = value
            .shared_key_cts
            .into_iter()
            .map(|ct| CSharedKeyCT::try_from(ct))
            .collect::<Result<_, _>>()?;
        shared_key_cts_vec.shrink_to_fit();
        let shared_key_cts = shared_key_cts_vec.as_mut_ptr();
        mem::forget(shared_key_cts_vec);
        let mut filepath_cts_vec: Vec<CFilePathCT> = value
            .filepath_cts
            .into_iter()
            .map(|ct| CFilePathCT::try_from(ct))
            .collect::<Result<_, _>>()?;
        filepath_cts_vec.shrink_to_fit();
        let filepath_cts = filepath_cts_vec.as_mut_ptr();
        mem::forget(filepath_cts_vec);
        let shared_key_hash = str2ptr(hex::encode(&value.shared_key_hash.0));
        let contents_ct = str2ptr(hex::encode(&value.contents_ct));
        Ok(Self {
            num_cts,
            shared_key_cts,
            filepath_cts,
            shared_key_hash,
            contents_ct,
        })
    }
}

impl TryInto<FileCT> for CFileCT {
    type Error = SommelierDriveCryptoError;
    fn try_into(self) -> Result<FileCT, Self::Error> {
        let num_cts = self.num_cts as usize;
        let shared_key_cts_slice = unsafe { slice::from_raw_parts(self.shared_key_cts, num_cts) };
        let shared_key_cts: Vec<Vec<u8>> = shared_key_cts_slice
            .into_iter()
            .map(|ct| ct.clone().try_into())
            .collect::<Result<_, _>>()?;
        let filepath_cts_slice = unsafe { slice::from_raw_parts(self.filepath_cts, num_cts) };
        let filepath_cts: Vec<FilePathCT> = filepath_cts_slice
            .into_iter()
            .map(|ct| ct.clone().try_into())
            .collect::<Result<_, _>>()?;
        let shared_key_hash = HashDigest::try_from(ptr2str(self.shared_key_hash).to_string())?;
        let contents_ct = hex::decode(ptr2str(self.contents_ct))?;
        Ok(FileCT {
            shared_key_cts,
            filepath_cts,
            shared_key_hash,
            contents_ct,
        })
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CPermissionCT {
    pub shared_key_ct: CSharedKeyCT,
    pub filepath_ct: CFilePathCT,
}

impl Default for CPermissionCT {
    fn default() -> Self {
        Self {
            shared_key_ct: CSharedKeyCT::default(),
            filepath_ct: CFilePathCT::default(),
        }
    }
}

impl TryFrom<PermissionCT> for CPermissionCT {
    type Error = SommelierDriveCryptoError;
    fn try_from(value: PermissionCT) -> Result<Self, Self::Error> {
        let shared_key_ct = value.shared_key_ct.try_into()?;
        let filepath_ct = value.filepath_ct.try_into()?;
        Ok(Self {
            shared_key_ct,
            filepath_ct,
        })
    }
}

impl TryInto<PermissionCT> for CPermissionCT {
    type Error = SommelierDriveCryptoError;
    fn try_into(self) -> Result<PermissionCT, Self::Error> {
        let shared_key_ct = self.shared_key_ct.try_into()?;
        let filepath_ct = self.filepath_ct.try_into()?;
        Ok(PermissionCT {
            shared_key_ct,
            filepath_ct,
        })
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CRecoveredSharedKey {
    pub shared_key: *mut c_char,
    pub shared_key_hash: *mut c_char,
}

impl Default for CRecoveredSharedKey {
    fn default() -> Self {
        Self {
            shared_key: ptr::null_mut(),
            shared_key_hash: ptr::null_mut(),
        }
    }
}

impl TryFrom<RecoveredSharedKey> for CRecoveredSharedKey {
    type Error = SommelierDriveCryptoError;
    fn try_from(value: RecoveredSharedKey) -> Result<Self, Self::Error> {
        let shared_key = str2ptr(value.shared_key.into());
        let shared_key_hash = str2ptr(value.shared_key_hash.into());
        Ok(Self {
            shared_key,
            shared_key_hash,
        })
    }
}

impl TryInto<RecoveredSharedKey> for CRecoveredSharedKey {
    type Error = SommelierDriveCryptoError;
    fn try_into(self) -> Result<RecoveredSharedKey, Self::Error> {
        let shared_key = SymmetricKey::try_from(ptr2str(self.shared_key).to_string())?;
        let shared_key_hash = HashDigest::try_from(ptr2str(self.shared_key_hash).to_string())?;
        Ok(RecoveredSharedKey {
            shared_key,
            shared_key_hash,
        })
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CSharedKeyCT {
    pub ptr: *mut c_char,
}

impl Default for CSharedKeyCT {
    fn default() -> Self {
        Self {
            ptr: ptr::null_mut(),
        }
    }
}

impl TryFrom<Vec<u8>> for CSharedKeyCT {
    type Error = SommelierDriveCryptoError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self {
            ptr: str2ptr(hex::encode(&value)),
        })
    }
}

impl TryInto<Vec<u8>> for CSharedKeyCT {
    type Error = SommelierDriveCryptoError;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let str = ptr2str(self.ptr);
        let vec = hex::decode(str)?;
        Ok(vec)
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CFilePathCT {
    pub ptr: *mut c_char,
}

impl Default for CFilePathCT {
    fn default() -> Self {
        Self {
            ptr: ptr::null_mut(),
        }
    }
}

impl TryFrom<FilePathCT> for CFilePathCT {
    type Error = SommelierDriveCryptoError;
    fn try_from(value: FilePathCT) -> Result<Self, Self::Error> {
        let s: String = value.clone().into();
        Ok(Self {
            ptr: str2ptr(value.into()),
        })
    }
}

impl TryInto<FilePathCT> for CFilePathCT {
    type Error = SommelierDriveCryptoError;
    fn try_into(self) -> Result<FilePathCT, Self::Error> {
        let str = ptr2str(self.ptr);
        let ct = FilePathCT::try_from(str.to_string())?;
        Ok(ct)
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CContentsBytes {
    pub ptr: *const u8,
    pub len: usize,
}

easy_ffi!(fn_str_pointer =>
    |err| {
        return str2ptr(String::new())
    }
    |panic_val| {
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-cryptos-panic: {}",s),
            None => panic!("sommelier-drive-cryptos-panic without an error message"),
        }
    }
);

fn_str_pointer!(
    fn pkeGenSecretKey() -> Result<*mut c_char, SommelierDriveCryptoError> {
        let mut rng = OsRng;
        let sk = pke_gen_secret_key(&mut rng)?;
        let sk_str = sk.try_into()?;
        Ok(str2ptr(sk_str))
    }
);

fn_str_pointer!(
    fn pkeGenPublicKey(sk: *mut c_char) -> Result<*mut c_char, SommelierDriveCryptoError> {
        let sk = PkeSecretKey::try_from(ptr2str(sk).to_string())?;
        let pk = pke_gen_public_key(&sk);
        let pk_str = pk.try_into()?;
        Ok(str2ptr(pk_str))
    }
);

fn_str_pointer!(
    fn pkeGenSignature(
        sk: *mut c_char,
        region_name: *mut c_char,
        method: *mut c_char,
        uri: *mut c_char,
        fields: *mut *mut c_char,
        vals: *mut *mut c_char,
        num_field: usize,
    ) -> Result<*mut c_char, SommelierDriveCryptoError> {
        let sk = PkeSecretKey::try_from(ptr2str(sk).to_string())?;
        let region_name = ptr2str(region_name);
        let method = ptr2str(method);
        let uri = ptr2str(uri);
        let fields_slice = unsafe { slice::from_raw_parts_mut(fields, num_field) };
        let fields = fields_slice
            .into_iter()
            .map(|ptr| ptr2str(*ptr))
            .collect::<Vec<&str>>();
        let vals_slice = unsafe { slice::from_raw_parts_mut(vals, num_field) };
        let vals = vals_slice
            .into_iter()
            .map(|ptr| ptr2str(*ptr))
            .collect::<Vec<&str>>();
        let mut field_vals = BTreeMap::new();
        for (field, val) in fields.into_iter().zip(vals) {
            field_vals.insert(field, val);
        }
        let mut rng = OsRng;
        let signature = gen_signature(&sk, region_name, method, uri, field_vals, &mut rng);
        let sign_str = serde_json::to_string(&signature)?;
        Ok(str2ptr(sign_str))
    }
);

easy_ffi!(fn_permission_int_pointer =>
    |err| {
        return -1;
    }
    |panic_val| {
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-cryptos-panic: {}",s),
            None => panic!("sommelier-drive-cryptos-panic without an error message"),
        }
    }
);

fn_permission_int_pointer!(
    fn verifySignature(
        pk: *mut c_char,
        region_name: *mut c_char,
        method: *mut c_char,
        uri: *mut c_char,
        fields: *mut *mut c_char,
        vals: *mut *mut c_char,
        num_field: usize,
        signature: *mut c_char,
    ) -> Result<c_int, SommelierDriveCryptoError> {
        let pk = PkePublicKey::try_from(ptr2str(pk).to_string())?;
        let region_name = ptr2str(region_name);
        let method = ptr2str(method);
        let uri = ptr2str(uri);
        let fields_slice = unsafe { slice::from_raw_parts_mut(fields, num_field) };
        let fields = fields_slice
            .into_iter()
            .map(|ptr| ptr2str(*ptr))
            .collect::<Vec<&str>>();
        let vals_slice = unsafe { slice::from_raw_parts_mut(vals, num_field) };
        let vals = vals_slice
            .into_iter()
            .map(|ptr| ptr2str(*ptr))
            .collect::<Vec<&str>>();
        let mut field_vals = BTreeMap::new();
        for (field, val) in fields.into_iter().zip(vals) {
            field_vals.insert(field, val);
        }
        let signature = serde_json::from_str::<Vec<u8>>(ptr2str(signature))?;
        let verified = verify_signature(&pk, region_name, method, uri, field_vals, &signature)?;
        if verified {
            Ok(1)
        } else {
            Ok(0)
        }
    }
);

easy_ffi!(fn_file_ct_pointer =>
    |err| {
        return CFileCT::default();
    }
    |panic_val| {
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-cryptos-panic: {}",s),
            None => panic!("sommelier-drive-cryptos-panic without an error message"),
        }
    }
);

fn_file_ct_pointer!(
    fn encryptNewFile(
        pks: *mut *mut c_char,
        num_pk: usize,
        filepath: *mut c_char,
        contents: CContentsBytes,
    ) -> Result<CFileCT, SommelierDriveCryptoError> {
        let pks_slice = unsafe { slice::from_raw_parts_mut(pks, num_pk) };
        let pks: Vec<PkePublicKey> = pks_slice
            .into_iter()
            .map(|ptr| PkePublicKey::try_from(ptr2str(*ptr).to_string()))
            .collect::<Result<_, _>>()?;
        let filepath = ptr2str(filepath);
        let contents_bytes = unsafe { slice::from_raw_parts(contents.ptr, contents.len) };
        let file_ct = encrypt_new_file(&pks, filepath, contents_bytes)?;
        let c_file_ct = CFileCT::try_from(file_ct)?;
        Ok(c_file_ct)
    }
);

easy_ffi!(fn_recovered_shared_key_pointer =>
    |err| {
        return CRecoveredSharedKey::default();
    }
    |panic_val| {
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-cryptos-panic: {}",s),
            None => panic!("sommelier-drive-cryptos-panic without an error message"),
        }
    }
);

fn_recovered_shared_key_pointer!(
    fn recoverSharedKey(
        sk: *mut c_char,
        ct: CSharedKeyCT,
    ) -> Result<CRecoveredSharedKey, SommelierDriveCryptoError> {
        let sk = PkeSecretKey::try_from(ptr2str(sk).to_string())?;
        let ct: Vec<u8> = ct.try_into()?;
        let recovered_shared_key = recover_shared_key(&sk, &ct)?;
        Ok(recovered_shared_key.try_into()?)
    }
);

easy_ffi!(fn_contents_bytes_pointer =>
    |err| {
        return CContentsBytes {
            ptr: ptr::null(),
            len: 0
        }
    }
    |panic_val| {
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-cryptos-panic: {}",s),
            None => panic!("sommelier-drive-cryptos-panic without an error message"),
        }
    }
);

fn_contents_bytes_pointer!(
    fn decryptContentsCT(
        shared_key: CRecoveredSharedKey,
        ct: *mut c_char,
    ) -> Result<CContentsBytes, SommelierDriveCryptoError> {
        let shared_key = shared_key.try_into()?;
        let ct = hex::decode(ptr2str(ct))?;
        let mut contents = decrypt_contents_ct(&shared_key, &ct)?;
        contents.shrink_to_fit();
        let contents_ptr = contents.as_ptr();
        let contents_bytes_len = contents.len();
        mem::forget(contents);
        let contents_bytes = CContentsBytes {
            ptr: contents_ptr,
            len: contents_bytes_len,
        };
        Ok(contents_bytes)
    }
);

easy_ffi!(fn_permission_ct_pointer =>
    |err| {
        return CPermissionCT::default();
    }
    |panic_val| {
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-cryptos-panic: {}",s),
            None => panic!("sommelier-drive-cryptos-panic without an error message"),
        }
    }
);

fn_str_pointer!(
    fn encryptNewFileWithSharedKey(
        recovered_shared_key: CRecoveredSharedKey,
        contents: CContentsBytes,
    ) -> Result<*mut c_char, SommelierDriveCryptoError> {
        let recovered_shared_key = recovered_shared_key.try_into()?;
        let contents_bytes = unsafe { slice::from_raw_parts(contents.ptr, contents.len) };
        let contents_ct = encrypt_new_file_with_shared_key(&recovered_shared_key, &contents_bytes)?;
        Ok(str2ptr(hex::encode(&contents_ct)))
    }
);

fn_permission_ct_pointer!(
    fn addPermission(
        pk: *mut c_char,
        recovered_shared_key: CRecoveredSharedKey,
        filepath: *mut c_char,
    ) -> Result<CPermissionCT, SommelierDriveCryptoError> {
        let pk = PkePublicKey::try_from(ptr2str(pk).to_string())?;
        let recovered_shared_key = recovered_shared_key.try_into()?;
        let filepath = ptr2str(filepath);
        let permission_ct = add_permission(&pk, &recovered_shared_key, filepath)?;
        Ok(permission_ct.try_into()?)
    }
);

easy_ffi!(fn_filepath_ct_pointer =>
    |err| {
        return CFilePathCT::default();
    }
    |panic_val| {
        match panic_val.downcast_ref::<&'static str>() {
            Some(s) => panic!("sommelier-drive-cryptos-panic: {}",s),
            None => panic!("sommelier-drive-cryptos-panic without an error message"),
        }
    }
);

fn_filepath_ct_pointer!(
    fn encryptFilepath(
        pk: *mut c_char,
        filepath: *mut c_char,
    ) -> Result<CFilePathCT, SommelierDriveCryptoError> {
        let pk = PkePublicKey::try_from(ptr2str(pk).to_string())?;
        let filepath = ptr2str(filepath);
        let ct = encrypt_filepath(&pk, filepath)?;
        Ok(ct.try_into()?)
    }
);

fn_str_pointer!(
    fn decryptFilepathCT(
        sk: *mut c_char,
        ct: CFilePathCT,
    ) -> Result<*mut c_char, SommelierDriveCryptoError> {
        let sk = PkeSecretKey::try_from(ptr2str(sk).to_string())?;
        let ct = ct.try_into()?;
        let filepath = decrypt_filepath_ct(&sk, &ct)?;
        Ok(str2ptr(filepath))
    }
);

fn_str_pointer!(
    fn computePermissionHash(
        user_id: c_uint,
        parent_filepath: *mut c_char,
    ) -> Result<*mut c_char, SommelierDriveCryptoError> {
        let parent_filepath = ptr2str(parent_filepath);
        let hash_bytes = compute_permission_hash(user_id as u64, parent_filepath);
        let hash_str = hash_bytes.into();
        Ok(str2ptr(hash_str))
    }
);

fn str2ptr(str: String) -> *mut c_char {
    let c_str = CString::new(str).unwrap();
    c_str.into_raw()
}

fn ptr2str<'a>(ptr: *mut c_char) -> &'a str {
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str().unwrap()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn c_file_test() {
        let sk = pkeGenSecretKey();
        let pk = pkeGenPublicKey(sk);

        let mut pks = [pk];
        let filepath = CString::new("/test/filepath_test/test.txt").unwrap();
        let text_bytes = b"Hello, World!";
        let text_len = text_bytes.len();
        let contents = CContentsBytes {
            ptr: text_bytes.as_ptr(),
            len: text_len,
        };
        let ct = encryptNewFile(pks.as_mut_ptr(), 1, filepath.clone().into_raw(), contents);

        let shared_key_cts = unsafe { slice::from_raw_parts_mut(ct.shared_key_cts, 1) };
        let recovered_shared_key = recoverSharedKey(sk, shared_key_cts[0].clone());
        let decrypted_contents = decryptContentsCT(recovered_shared_key, ct.contents_ct);
        let decrypted_text_bytes =
            unsafe { slice::from_raw_parts(decrypted_contents.ptr, decrypted_contents.len) };
        assert_eq!(decrypted_text_bytes, text_bytes);
    }

    #[test]
    fn c_encrypt_new_file_with_shared_key_test() {
        let sk = pkeGenSecretKey();
        let pk = pkeGenPublicKey(sk);

        let mut pks = [pk];
        let filepath = CString::new("/test/filepath_test/test.txt").unwrap();
        let text_bytes = b"Hello, World!";
        let text_len = text_bytes.len();
        let contents = CContentsBytes {
            ptr: text_bytes.as_ptr(),
            len: text_len,
        };
        let ct = encryptNewFile(pks.as_mut_ptr(), 1, filepath.clone().into_raw(), contents);

        let shared_key_cts = unsafe { slice::from_raw_parts_mut(ct.shared_key_cts, 1) };
        let recovered_shared_key = recoverSharedKey(sk, shared_key_cts[0].clone());

        let new_text_bytes = b"Hello, World?";
        let new_contents = CContentsBytes {
            ptr: new_text_bytes.as_ptr(),
            len: text_len,
        };
        let new_ct = encryptNewFileWithSharedKey(recovered_shared_key.clone(), new_contents);
        let decrypted_contents = decryptContentsCT(recovered_shared_key, new_ct);
        let decrypted_text_bytes =
            unsafe { slice::from_raw_parts(decrypted_contents.ptr, decrypted_contents.len) };
        assert_eq!(decrypted_text_bytes, new_text_bytes);
        assert_ne!(decrypted_text_bytes, text_bytes);
    }

    #[test]
    fn c_permission_test() {
        let sk = pkeGenSecretKey();
        let pk = pkeGenPublicKey(sk);

        let mut pks = [pk];
        let filepath = CString::new("/test/filepath_test/test.txt").unwrap();
        let text_bytes = b"Hello, World!";
        let text_len = text_bytes.len();
        let contents = CContentsBytes {
            ptr: text_bytes.as_ptr(),
            len: text_len,
        };
        let ct = encryptNewFile(pks.as_mut_ptr(), 1, filepath.clone().into_raw(), contents);

        let shared_key_cts = unsafe { slice::from_raw_parts_mut(ct.shared_key_cts, 1) };
        let recovered_shared_key = recoverSharedKey(sk, shared_key_cts[0].clone());

        let new_sk = pkeGenSecretKey();
        let new_pk = pkeGenPublicKey(new_sk);
        let new_permission_ct =
            addPermission(new_pk, recovered_shared_key, filepath.clone().into_raw());
        let recovered_shared_key = recoverSharedKey(new_sk, new_permission_ct.shared_key_ct);
        let contents = decryptContentsCT(recovered_shared_key, ct.contents_ct);
        let contents_bytes = unsafe { slice::from_raw_parts(contents.ptr, contents.len) };
        assert_eq!(text_bytes, contents_bytes);
    }

    #[test]
    fn c_filepath_test() {
        let sk = pkeGenSecretKey();
        let pk = pkeGenPublicKey(sk);
        let filepath = CString::new("/test/filepath_test/test.txt").unwrap();

        let ct = encryptFilepath(pk, filepath.clone().into_raw());
        let plaintext = decryptFilepathCT(sk, ct);
        let plaintext = unsafe { CString::from_raw(plaintext) };
        assert_eq!(filepath, plaintext);
    }

    #[test]
    fn c_sign_test() {
        let sk = pkeGenSecretKey();
        let pk = pkeGenPublicKey(sk);

        let region_name = CString::new("sign_test").unwrap();
        let method = CString::new("POST").unwrap();
        let uri = CString::new("/user").unwrap();
        let mut fields = vec![
            CString::new("dataPK").unwrap().into_raw(),
            CString::new("keywordPK").unwrap().into_raw(),
        ];
        let fields = fields.as_mut_ptr();
        let mut vals = vec![
            CString::new("pkd---").unwrap().into_raw(),
            CString::new("pkw---").unwrap().into_raw(),
        ];
        let vals = vals.as_mut_ptr();
        let signature = pkeGenSignature(
            sk,
            region_name.clone().into_raw(),
            method.clone().into_raw(),
            uri.clone().into_raw(),
            fields,
            vals,
            2,
        );

        let mut fields = vec![
            CString::new("keywordPK").unwrap().into_raw(),
            CString::new("dataPK").unwrap().into_raw(),
        ];
        let fields = fields.as_mut_ptr();
        let mut vals = vec![
            CString::new("pkw---").unwrap().into_raw(),
            CString::new("pkd---").unwrap().into_raw(),
        ];
        let vals = vals.as_mut_ptr();
        let verified = verifySignature(
            pk,
            region_name.clone().into_raw(),
            method.clone().into_raw(),
            uri.clone().into_raw(),
            fields,
            vals,
            2,
            signature,
        );
        assert_eq!(verified, 1);
        mem::drop(signature);
    }

    #[test]
    fn c_permission_hash_test() {
        let user_id_1 = 1;
        let user_id_2 = 2;
        let parent_filepath = CString::new("/test/filepath_test").unwrap();
        let hash1 = computePermissionHash(user_id_1, parent_filepath.clone().into_raw());
        let hash2 = computePermissionHash(user_id_2, parent_filepath.clone().into_raw());
        let hash1_str = unsafe { CString::from_raw(hash1) };
        let hash2_str = unsafe { CString::from_raw(hash2) };
        assert_ne!(hash1_str, hash2_str);
    }

    #[test]
    fn c_large_file_test() {
        let sk = pkeGenSecretKey();
        let pk = pkeGenPublicKey(sk);

        let mut pks = [pk];
        let filepath = "a".to_string().repeat(64);
        let filepath = CString::new(filepath).unwrap();
        let text_bytes = [1; 1048576 * 2];
        let text_len = text_bytes.len();
        let contents = CContentsBytes {
            ptr: text_bytes.as_ptr(),
            len: text_len,
        };
        let ct = encryptNewFile(pks.as_mut_ptr(), 1, filepath.clone().into_raw(), contents);

        let shared_key_cts = unsafe { slice::from_raw_parts_mut(ct.shared_key_cts, 1) };
        let recovered_shared_key = recoverSharedKey(sk, shared_key_cts[0].clone());
        let decrypted_contents = decryptContentsCT(recovered_shared_key, ct.contents_ct);
        let decrypted_text_bytes =
            unsafe { slice::from_raw_parts(decrypted_contents.ptr, decrypted_contents.len) };
        assert_eq!(decrypted_text_bytes, text_bytes);
    }
}
