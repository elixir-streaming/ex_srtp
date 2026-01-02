use rustler::Atom;

use crate::{aes_cm_128_hmac_sha1_32, aes_cm_128_hmac_sha1_80};

#[derive(Debug)]
pub enum ProtectionProfile {
    AesCm128HmacSha1_80,
    AesCm128HmacSha1_32,
}

impl From<Atom> for ProtectionProfile {
    fn from(atom: Atom) -> Self {
        match atom {
            atom if aes_cm_128_hmac_sha1_80() == atom => ProtectionProfile::AesCm128HmacSha1_80,
            atom if aes_cm_128_hmac_sha1_32() == atom => ProtectionProfile::AesCm128HmacSha1_32,
            _ => panic!("Unsupported protection profile"),
        }
    }
}

impl ProtectionProfile {
    pub fn tag_size(&self) -> usize {
        match self {
            ProtectionProfile::AesCm128HmacSha1_80 => 10,
            ProtectionProfile::AesCm128HmacSha1_32 => 4,
        }
    }
}
