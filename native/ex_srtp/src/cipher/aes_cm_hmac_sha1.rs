use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;
use rustler::OwnedBinary;
use subtle::ConstantTimeEq;

use crate::{
    cipher::Cipher, key_derivation::aes_cm_key_derivation, protection_profile::ProtectionProfile,
    Aes128Ctr, HmacSha1,
};

const RTCP_INDEX_SIZE: usize = 4;
const RTCP_HEADER_SIZE: usize = 8;

pub(crate) struct AesCmHmacSha1Cipher {
    profile: ProtectionProfile,
    rtp_session_key: Vec<u8>,
    rtcp_session_key: Vec<u8>,
    rtp_salt: Vec<u8>,
    rtcp_salt: Vec<u8>,
    rtcp_auth_key: Vec<u8>,
    rtp_hasher: HmacSha1,
}

impl AesCmHmacSha1Cipher {
    pub fn new(profile: ProtectionProfile, master_key: &[u8], master_salt: &[u8]) -> Self {
        let rtp_auth_key = aes_cm_key_derivation(master_key, master_salt, 0x1, 20);

        AesCmHmacSha1Cipher {
            profile,
            rtp_session_key: aes_cm_key_derivation(master_key, master_salt, 0x0, 16),
            rtp_salt: aes_cm_key_derivation(master_key, master_salt, 0x2, 14),
            rtcp_session_key: aes_cm_key_derivation(master_key, master_salt, 0x3, 16),
            rtcp_auth_key: aes_cm_key_derivation(master_key, master_salt, 0x4, 20),
            rtcp_salt: aes_cm_key_derivation(master_key, master_salt, 0x5, 14),
            rtp_hasher: HmacSha1::new_from_slice(&rtp_auth_key.as_slice()).unwrap(),
        }
    }

    fn generate_rtp_auth_tag(&self, data: &[&[u8]]) -> Vec<u8> {
        let mut mac = self.rtp_hasher.clone();
        for chunk in data {
            mac.update(chunk);
        }
        return mac.finalize().into_bytes()[..self.profile.tag_size()].to_vec();
    }

    fn generate_rtcp_auth_tag(&self, data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha1::new_from_slice(self.rtcp_auth_key.as_slice()).unwrap();
        mac.update(data);
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

    fn rtcp_initialization_vector(salt: &[u8], ssrc: u32, index: u32) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[4..8].copy_from_slice(&ssrc.to_be_bytes());
        iv[10..14].copy_from_slice(&index.to_be_bytes());

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

        let auth_tag = self.generate_rtp_auth_tag(&[
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
        if payload.len() < self.profile.tag_size() {
            return Err("not_enough_data".to_string());
        }

        let (encrypted_data, auth_tag) = payload.split_at(payload.len() - self.profile.tag_size());
        let expected_tag = &self.generate_rtp_auth_tag(&[
            &header[..],
            &encrypted_data[..],
            &roc.to_be_bytes()[..],
        ]);

        if auth_tag.ct_eq(expected_tag).unwrap_u8() != 1 {
            return Err("authentication_failed".to_string());
        }

        let size = payload.len() - self.profile.tag_size();
        let mut owned_binary = OwnedBinary::new(size).unwrap();
        owned_binary
            .as_mut_slice()
            .copy_from_slice(&payload[..payload.len() - self.profile.tag_size()]);

        let iv = Self::initialization_vector(&self.rtp_salt, header, roc);
        Aes128Ctr::new(self.rtp_session_key.as_slice().into(), &iv.into())
            .apply_keystream(&mut owned_binary.as_mut_slice());

        return Ok(owned_binary);
    }

    fn encrypt_rtcp(&mut self, compound_packet: &[u8], index: u32) -> OwnedBinary {
        let ssrc = u32::from_be_bytes(compound_packet[4..8].try_into().unwrap());
        let mut index_bytes = index.to_be_bytes();
        index_bytes[0] |= 0x80;

        let size = compound_packet.len() + self.profile.tag_size() + RTCP_INDEX_SIZE;
        let mut owned_binary = OwnedBinary::new(size).unwrap();
        let slice = owned_binary.as_mut_slice();

        slice[..compound_packet.len()].copy_from_slice(compound_packet);
        slice[compound_packet.len()..compound_packet.len() + RTCP_INDEX_SIZE]
            .copy_from_slice(&index_bytes);

        let iv = Self::rtcp_initialization_vector(&self.rtcp_salt, ssrc, index);
        Aes128Ctr::new(self.rtcp_session_key.as_slice().into(), &iv.into())
            .apply_keystream(&mut slice[RTCP_HEADER_SIZE..compound_packet.len()]);

        let auth_tag =
            self.generate_rtcp_auth_tag(&slice[..compound_packet.len() + RTCP_INDEX_SIZE]);

        slice[compound_packet.len() + RTCP_INDEX_SIZE..].copy_from_slice(&auth_tag);
        owned_binary
    }

    fn decrypt_rtcp(&mut self, compound_packet: &[u8]) -> Result<OwnedBinary, String> {
        let tag_size = self.profile.tag_size();
        if compound_packet.len() < tag_size + RTCP_HEADER_SIZE + RTCP_INDEX_SIZE {
            return Err("not_enough_data".to_string());
        }

        let (data, auth_tag) = compound_packet.split_at(compound_packet.len() - tag_size);

        let expected_tag = &self.generate_rtcp_auth_tag(data);
        if auth_tag.ct_eq(expected_tag).unwrap_u8() != 1 {
            return Err("authentication_failed".to_string());
        }

        let (header, rest) = data.split_at(RTCP_HEADER_SIZE);
        let (encrypted_data, index_bytes) = rest.split_at(rest.len() - RTCP_INDEX_SIZE);
        let ssrc = u32::from_be_bytes(header[4..8].try_into().unwrap());
        let mut index = u32::from_be_bytes(index_bytes.try_into().unwrap());

        if index_bytes[0] & 0x80 == 0 {
            let mut owned_binary = OwnedBinary::new(data.len()).unwrap();
            owned_binary.as_mut_slice().copy_from_slice(data);
            return Ok(owned_binary);
        }

        index &= 0x7FFFFFFF;

        let size = header.len() + encrypted_data.len();
        let mut owned_binary = OwnedBinary::new(size).unwrap();
        owned_binary.as_mut_slice()[..RTCP_HEADER_SIZE].copy_from_slice(header);
        owned_binary.as_mut_slice()[RTCP_HEADER_SIZE..].copy_from_slice(encrypted_data);

        let iv = Self::rtcp_initialization_vector(&self.rtcp_salt, ssrc, index);
        Aes128Ctr::new(self.rtcp_session_key.as_slice().into(), &iv.into())
            .apply_keystream(&mut owned_binary.as_mut_slice()[RTCP_HEADER_SIZE..]);

        Ok(owned_binary)
    }
}
