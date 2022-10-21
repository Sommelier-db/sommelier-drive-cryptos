use crate::*;
use core::slice;
use easy_ffi::easy_ffi;
use std::collections::BTreeMap;
use std::ffi::*;
use std::mem;
use std::os::raw::c_char;
use std::os::raw::{c_int, c_uint};

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CFileCT {
    pub num_cts: c_uint,
    pub shared_key_cts: *mut CSharedKeyCT,
    pub filepath_cts: *mut CFilePathCT,
    pub shared_key_hash: *mut c_char,
    pub contents_ct: *mut c_char,
}

impl Default for CFileCT {
    fn default() -> Self {
        let mut shared_key_cts_vec = Vec::<CSharedKeyCT>::new();
        let shared_key_cts = shared_key_cts_vec.as_mut_ptr();
        mem::forget(shared_key_cts_vec);
        let mut filepath_cts_vec = Vec::<CFilePathCT>::new();
        let filepath_cts = filepath_cts_vec.as_mut_ptr();
        mem::forget(filepath_cts_vec);
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
        let num_cts = value.shared_key_cts.len() as c_uint;
        let mut shared_key_cts_vec: Vec<CSharedKeyCT> = value
            .shared_key_cts
            .into_iter()
            .map(|ct| CSharedKeyCT::try_from(ct))
            .collect::<Result<_, _>>()?;
        let shared_key_cts = shared_key_cts_vec.as_mut_ptr();
        mem::forget(shared_key_cts);
        let mut filepath_cts_vec: Vec<CFilePathCT> = value
            .filepath_cts
            .into_iter()
            .map(|ct| CFilePathCT::try_from(ct))
            .collect::<Result<_, _>>()?;
        let filepath_cts = filepath_cts_vec.as_mut_ptr();
        mem::forget(filepath_cts);
        let shared_key_hash = str2ptr(serde_json::to_string(&value.shared_key_hash)?);
        let contents_ct = str2ptr(serde_json::to_string(&value.contents_ct)?);
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
        let shared_key_hash = serde_json::from_str::<Vec<u8>>(ptr2str(self.shared_key_hash))?;
        let contents_ct = serde_json::from_str::<Vec<u8>>(ptr2str(self.contents_ct))?;
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
            shared_key: str2ptr(String::new()),
            shared_key_hash: str2ptr(String::new()),
        }
    }
}

impl TryFrom<RecoveredSharedKey> for CRecoveredSharedKey {
    type Error = SommelierDriveCryptoError;
    fn try_from(value: RecoveredSharedKey) -> Result<Self, Self::Error> {
        let shared_key = str2ptr(serde_json::to_string(&value.shared_key)?);
        let shared_key_hash = str2ptr(serde_json::to_string(&value.shared_key_hash)?);
        Ok(Self {
            shared_key,
            shared_key_hash,
        })
    }
}

impl TryInto<RecoveredSharedKey> for CRecoveredSharedKey {
    type Error = SommelierDriveCryptoError;
    fn try_into(self) -> Result<RecoveredSharedKey, Self::Error> {
        let shared_key = serde_json::from_str(&ptr2str(self.shared_key))?;
        let shared_key_hash = serde_json::from_str(&ptr2str(self.shared_key_hash))?;
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
            ptr: str2ptr(String::new()),
        }
    }
}

impl TryFrom<Vec<u8>> for CSharedKeyCT {
    type Error = SommelierDriveCryptoError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self {
            ptr: str2ptr(serde_json::to_string(&value)?),
        })
    }
}

impl TryInto<Vec<u8>> for CSharedKeyCT {
    type Error = SommelierDriveCryptoError;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let str = ptr2str(self.ptr);
        let vec = serde_json::from_str::<Vec<u8>>(str)?;
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
            ptr: str2ptr(String::new()),
        }
    }
}

impl TryFrom<FilePathCT> for CFilePathCT {
    type Error = SommelierDriveCryptoError;
    fn try_from(value: FilePathCT) -> Result<Self, Self::Error> {
        Ok(Self {
            ptr: str2ptr(serde_json::to_string(&value)?),
        })
    }
}

impl TryInto<FilePathCT> for CFilePathCT {
    type Error = SommelierDriveCryptoError;
    fn try_into(self) -> Result<FilePathCT, Self::Error> {
        let str = ptr2str(self.ptr);
        let ct = serde_json::from_str::<FilePathCT>(str)?;
        Ok(ct)
    }
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
        let sk_str = serde_json::to_string(&sk)?;
        Ok(str2ptr(sk_str))
    }
);

fn_str_pointer!(
    fn pkeGenPublicKey(sk: *mut c_char) -> Result<*mut c_char, SommelierDriveCryptoError> {
        let sk = serde_json::from_str::<PkeSecretKey>(&ptr2str(sk))?;
        let pk = pke_gen_public_key(&sk);
        let pk_str = serde_json::to_string(&pk)?;
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
        num_field: c_uint,
    ) -> Result<*mut c_char, SommelierDriveCryptoError> {
        let sk = serde_json::from_str::<PkeSecretKey>(&ptr2str(sk))?;
        let region_name = ptr2str(region_name);
        let method = ptr2str(method);
        let uri = ptr2str(uri);
        let num_field = num_field.try_into().unwrap();
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
            field_vals.insert(field.to_string(), val.to_string());
        }
        let mut rng = OsRng;
        let signature = gen_signature(&sk, region_name, method, uri, &field_vals, &mut rng);
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
        num_field: c_uint,
        signature: *mut c_char,
    ) -> Result<c_int, SommelierDriveCryptoError> {
        let pk = serde_json::from_str::<PkePublicKey>(&ptr2str(pk))?;
        let region_name = ptr2str(region_name);
        let method = ptr2str(method);
        let uri = ptr2str(uri);
        let num_field = num_field.try_into().unwrap();
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
            field_vals.insert(field.to_string(), val.to_string());
        }
        let signature = serde_json::from_str::<Vec<u8>>(ptr2str(signature))?;
        let verified = verify_signature(&pk, region_name, method, uri, &field_vals, &signature)?;
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
        num_pk: c_uint,
        filepath: *mut c_char,
        contents_bytes: *mut u8,
        contents_bytes_size: c_uint,
    ) -> Result<CFileCT, SommelierDriveCryptoError> {
        let pks_slice = unsafe { slice::from_raw_parts_mut(pks, num_pk as usize) };
        let pks: Vec<PkePublicKey> = pks_slice
            .into_iter()
            .map(|ptr| serde_json::from_str::<PkePublicKey>(&ptr2str(*ptr)))
            .collect::<Result<_, _>>()?;
        let filepath = ptr2str(filepath);
        let contents_bytes =
            unsafe { slice::from_raw_parts_mut(contents_bytes, contents_bytes_size as usize) };
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
        let sk = serde_json::from_str::<PkeSecretKey>(&ptr2str(sk))?;
        let ct: Vec<u8> = ct.try_into()?;
        let recovered_shared_key = recover_shared_key(&sk, &ct)?;
        Ok(recovered_shared_key.try_into()?)
    }
);

fn_str_pointer!(
    fn decryptContentsCT(
        shared_key: CRecoveredSharedKey,
        ct: *mut c_char,
    ) -> Result<*mut c_char, SommelierDriveCryptoError> {
        let shared_key = shared_key.try_into()?;
        let ct = serde_json::from_str::<Vec<u8>>(ptr2str(ct))?;
        let contents = decrypt_contents_ct(&shared_key, &ct)?;
        Ok(str2ptr(serde_json::to_string::<Vec<u8>>(&contents)?))
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
        contents_bytes: *mut u8,
        contents_bytes_size: c_uint,
    ) -> Result<*mut c_char, SommelierDriveCryptoError> {
        let recovered_shared_key = recovered_shared_key.try_into()?;
        let contents_bytes =
            unsafe { slice::from_raw_parts_mut(contents_bytes, contents_bytes_size as usize) };
        let contents_ct = encrypt_new_file_with_shared_key(&recovered_shared_key, &contents_bytes)?;
        Ok(str2ptr(serde_json::to_string(&contents_ct)?))
    }
);

fn_permission_ct_pointer!(
    fn addPermission(
        pk: *mut c_char,
        recovered_shared_key: CRecoveredSharedKey,
        filepath: *mut c_char,
    ) -> Result<CPermissionCT, SommelierDriveCryptoError> {
        let pk = serde_json::from_str::<PkePublicKey>(ptr2str(pk))?;
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
        let pk = serde_json::from_str::<PkePublicKey>(ptr2str(pk))?;
        let filepath = ptr2str(filepath);
        let ct = encrypt_filepath(&pk, filepath)?;
        Ok(ct.try_into()?)
    }
);

fn_str_pointer!(
    fn decryptFilepath(
        sk: *mut c_char,
        ct: CFilePathCT,
    ) -> Result<*mut c_char, SommelierDriveCryptoError> {
        let sk = serde_json::from_str::<PkeSecretKey>(ptr2str(sk))?;
        let ct = ct.try_into()?;
        let filepath = decrypt_filepath_ct(&sk, &ct)?;
        Ok(str2ptr(filepath))
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
