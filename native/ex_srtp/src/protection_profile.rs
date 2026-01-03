use rustler::{atoms, Atom};

atoms! {
    aes_cm_128_hmac_sha1_80,
    aes_cm_128_hmac_sha1_32,
    aes_gcm_128_16_auth,
}

#[derive(Debug)]
pub(crate) enum ProtectionProfile {
    AesCm128HmacSha1_80,
    AesCm128HmacSha1_32,
    AesGcm128_16,
}

impl From<Atom> for ProtectionProfile {
    fn from(atom: Atom) -> Self {
        match atom {
            atom if aes_cm_128_hmac_sha1_80() == atom => ProtectionProfile::AesCm128HmacSha1_80,
            atom if aes_cm_128_hmac_sha1_32() == atom => ProtectionProfile::AesCm128HmacSha1_32,
            atom if aes_gcm_128_16_auth() == atom => ProtectionProfile::AesGcm128_16,
            _ => panic!("Unsupported protection profile"),
        }
    }
}

impl ProtectionProfile {
    pub fn tag_size(&self) -> usize {
        match self {
            ProtectionProfile::AesCm128HmacSha1_80 => 10,
            ProtectionProfile::AesCm128HmacSha1_32 => 4,
            ProtectionProfile::AesGcm128_16 => 16,
        }
    }
}
