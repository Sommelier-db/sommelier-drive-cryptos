use crate::SommelierDriveCryptoError;

pub trait HexString: Sized {
    fn from_str(value: &str) -> Result<Self, SommelierDriveCryptoError>;
    fn to_string(&self) -> String;
}

pub trait PemString: Sized {
    fn from_str(value: &str) -> Result<Self, SommelierDriveCryptoError>;
    fn to_string(&self) -> Result<String, SommelierDriveCryptoError>;
}
