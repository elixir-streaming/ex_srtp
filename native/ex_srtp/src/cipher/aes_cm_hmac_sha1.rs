use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;
use rustler::OwnedBinary;

use crate::{
    cipher::Cipher, key_derivation::aes_cm_key_derivation, protection_profile::ProtectionProfile,
    Aes128Ctr, HmacSha1,
};

pub(crate) struct AesCmHmacSha1Cipher {
    pub profile: ProtectionProfile,
    pub rtp_session_key: Vec<u8>,
    pub rtcp_session_key: Vec<u8>,
    pub rtp_salt: Vec<u8>,
    pub rtcp_salt: Vec<u8>,
    pub rtp_auth_key: Vec<u8>,
    pub rtcp_auth_key: Vec<u8>,
}

impl AesCmHmacSha1Cipher {
    pub fn new(profile: ProtectionProfile, master_key: &[u8], master_salt: &[u8]) -> Self {
        AesCmHmacSha1Cipher {
            profile,
            rtp_session_key: aes_cm_key_derivation(master_key, master_salt, 0x0, 16),
            rtp_auth_key: aes_cm_key_derivation(master_key, master_salt, 0x1, 20),
            rtp_salt: aes_cm_key_derivation(master_key, master_salt, 0x2, 14),
            rtcp_session_key: aes_cm_key_derivation(master_key, master_salt, 0x3, 16),
            rtcp_auth_key: aes_cm_key_derivation(master_key, master_salt, 0x4, 20),
            rtcp_salt: aes_cm_key_derivation(master_key, master_salt, 0x5, 14),
        }
    }

    fn calculate_auth_tag(&self, data: &[&[u8]]) -> Vec<u8> {
        let mut mac = HmacSha1::new_from_slice(self.rtp_auth_key.as_slice()).unwrap();
        for chunk in data {
            mac.update(chunk);
        }
        return mac.finalize().into_bytes()[..self.profile.tag_size()].to_vec();
    }

    fn initialization_vector(salt: &[u8], header: &[u8], roc: u32) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[4..8].copy_from_slice(&header[8..12]);
        iv[8..12].copy_from_slice(&roc.to_be_bytes());
        iv[12..14].copy_from_slice(&header[2..4]);

        for i in 0..salt.len() {
            iv[i] ^= salt[i];
        }

        iv
    }
}

impl Cipher for AesCmHmacSha1Cipher {
    fn encrypt_rtp(&mut self, header: &[u8], payload: &[u8], roc: u32) -> OwnedBinary {
        let size = header.len() + payload.len() + self.profile.tag_size();
        let mut owned_binary = OwnedBinary::new(size).unwrap();
        owned_binary.as_mut_slice()[..header.len()].copy_from_slice(header);
        owned_binary.as_mut_slice()[header.len()..header.len() + payload.len()]
            .copy_from_slice(payload);

        let iv = Self::initialization_vector(&self.rtp_salt, header, roc);
        Aes128Ctr::new(self.rtp_session_key.as_slice().into(), &iv.into())
            .apply_keystream(&mut owned_binary[header.len()..header.len() + payload.len()]);

        let auth_tag = self.calculate_auth_tag(&[
            &header,
            &owned_binary.as_slice()[header.len()..header.len() + payload.len()],
            &roc.to_be_bytes(),
        ]);

        owned_binary.as_mut_slice()[header.len() + payload.len()..].copy_from_slice(&auth_tag);
        return owned_binary;
    }

    fn decrypt_rtp(
        &mut self,
        header: &[u8],
        payload: &[u8],
        roc: u32,
    ) -> Result<OwnedBinary, String> {
        let (encrypted_data, auth_tag) = payload.split_at(payload.len() - self.profile.tag_size());
        let expected_tag =
            self.calculate_auth_tag(&[&header[..], &encrypted_data[..], &roc.to_be_bytes()[..]]);

        if auth_tag != expected_tag.as_slice() {
            return Err("authentication_failed".to_string());
        }

        let size = payload.len() - self.profile.tag_size();
        let mut owned_binary = OwnedBinary::new(size).unwrap();
        // owned_binary.as_mut_slice()[..header.len()].copy_from_slice(header);
        owned_binary
            .as_mut_slice()
            .copy_from_slice(&payload[..payload.len() - self.profile.tag_size()]);

        let iv = Self::initialization_vector(&self.rtp_salt, header, roc);
        Aes128Ctr::new(self.rtp_session_key.as_slice().into(), &iv.into())
            .apply_keystream(&mut owned_binary.as_mut_slice());

        return Ok(owned_binary);
    }
}
