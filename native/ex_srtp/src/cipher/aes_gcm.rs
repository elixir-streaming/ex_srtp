use aes_gcm::{aead::AeadMutInPlace, Aes128Gcm, KeyInit};
use rustler::OwnedBinary;

use crate::{
    cipher::Cipher, key_derivation::aes_cm_key_derivation, protection_profile::ProtectionProfile,
};

pub(crate) struct AesGcmCipher {
    profile: ProtectionProfile,
    rtp_session_key: Vec<u8>,
    rtcp_session_key: Vec<u8>,
    rtp_salt: Vec<u8>,
    rtcp_salt: Vec<u8>,
}

impl AesGcmCipher {
    pub fn new(profile: ProtectionProfile, master_key: &[u8], master_salt: &[u8]) -> Self {
        AesGcmCipher {
            profile,
            rtp_session_key: aes_cm_key_derivation(master_key, master_salt, 0x0, 16),
            rtp_salt: aes_cm_key_derivation(master_key, master_salt, 0x2, 12),
            rtcp_session_key: aes_cm_key_derivation(master_key, master_salt, 0x3, 16),
            rtcp_salt: aes_cm_key_derivation(master_key, master_salt, 0x5, 12),
        }
    }

    fn rtp_initialization_vector(&self, header: &[u8], roc: u32) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[2..6].copy_from_slice(&header[8..12]);
        iv[6..10].copy_from_slice(&roc.to_be_bytes());
        iv[10..12].copy_from_slice(&header[2..4]);

        for i in 0..iv.len() {
            iv[i] ^= self.rtp_salt[i];
        }

        iv
    }
}

impl Cipher for AesGcmCipher {
    fn encrypt_rtp(&mut self, header: &[u8], payload: &[u8], roc: u32) -> OwnedBinary {
        let mut cowned_binary =
            OwnedBinary::new(header.len() + payload.len() + self.profile.tag_size()).unwrap();
        let slice = cowned_binary.as_mut_slice();
        slice[..header.len()].copy_from_slice(header);
        slice[header.len()..header.len() + payload.len()].copy_from_slice(payload);

        let iv = self.rtp_initialization_vector(header, roc);
        let auth_tag = Aes128Gcm::new_from_slice(&self.rtp_session_key)
            .unwrap()
            .encrypt_in_place_detached(
                &iv.into(),
                header,
                &mut slice[header.len()..header.len() + payload.len()],
            )
            .unwrap();

        slice[header.len() + payload.len()..].copy_from_slice(&auth_tag);
        return cowned_binary;
    }

    fn decrypt_rtp(
        &mut self,
        header: &[u8],
        payload: &[u8],
        roc: u32,
    ) -> Result<rustler::OwnedBinary, String> {
        let tag_size = self.profile.tag_size();
        let mut owned_binary = OwnedBinary::new(payload.len() - tag_size).unwrap();
        let slice = owned_binary.as_mut_slice();
        slice.copy_from_slice(&payload[..payload.len() - tag_size]);

        let iv = self.rtp_initialization_vector(header, roc);
        Aes128Gcm::new_from_slice(&self.rtp_session_key)
            .unwrap()
            .decrypt_in_place_detached(
                &iv.into(),
                header,
                slice,
                payload[payload.len() - tag_size..].into(),
            )
            .map_err(|_| "authentication_failed".to_string())?;

        Ok(owned_binary)
    }

    fn encrypt_rtcp(&mut self, _compound_packet: &[u8], _index: u32) -> rustler::OwnedBinary {
        unimplemented!("AES-GCM RTCP encryption is not implemented yet")
    }

    fn decrypt_rtcp(&mut self, _compound_packet: &[u8]) -> Result<rustler::OwnedBinary, String> {
        unimplemented!("AES-GCM RTCP decryption is not implemented yet")
    }
}
