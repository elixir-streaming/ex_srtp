use rustler::OwnedBinary;

use crate::protection_profile::ProtectionProfile;

pub mod aes_cm_hmac_sha1;
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub mod aes_gcm;

pub(crate) fn create_cipher(policy: &crate::SrtpPolicy) -> Box<dyn Cipher + Send> {
    let master_key = policy.master_key.as_slice();
    let master_salt = policy.master_salt.as_slice();
    let profile: ProtectionProfile = policy.profile.into();

    match profile {
        ProtectionProfile::AesCm128HmacSha1_80 | ProtectionProfile::AesCm128HmacSha1_32 => {
            Box::new(aes_cm_hmac_sha1::AesCmHmacSha1Cipher::new(
                profile,
                master_key,
                master_salt,
            ))
        }

        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        ProtectionProfile::AesGcm128_16 => {
            Box::new(aes_gcm::AesGcmCipher::new(profile, master_key, master_salt))
        }

        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        ProtectionProfile::AesGcm128_16 => {
            panic!("AES-GCM is only supported on aarch64 and x86_64 architectures")
        }
    }
}

pub(crate) trait Cipher {
    fn encrypt_rtp(&mut self, header: &[u8], payload: &[u8], roc: u32) -> OwnedBinary;

    fn decrypt_rtp(
        &mut self,
        header: &[u8],
        payload: &[u8],
        roc: u32,
    ) -> Result<OwnedBinary, String>;

    fn encrypt_rtcp(&mut self, compound_packet: &[u8], index: u32) -> OwnedBinary;

    fn decrypt_rtcp(&mut self, compound_packet: &[u8]) -> Result<OwnedBinary, String>;
}
