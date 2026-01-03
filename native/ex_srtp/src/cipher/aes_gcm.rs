use rustler::OwnedBinary;

const RTCP_INDEX_SIZE: usize = 4;

use crate::{
    cipher::Cipher, key_derivation::aes_cm_key_derivation, protection_profile::ProtectionProfile,
};

pub(crate) struct AesGcmCipher {
    profile: ProtectionProfile,
    rtp_salt: Vec<u8>,
    rtcp_salt: Vec<u8>,
    rtp_c: graviola::aead::AesGcm,
    rtcp_c: graviola::aead::AesGcm,
}

impl AesGcmCipher {
    pub fn new(profile: ProtectionProfile, master_key: &[u8], master_salt: &[u8]) -> Self {
        let rtp_session_key = aes_cm_key_derivation(master_key, master_salt, 0x0, 16);
        let rtcp_session_key = aes_cm_key_derivation(master_key, master_salt, 0x3, 16);
        let rtp_c = graviola::aead::AesGcm::new(&rtp_session_key);
        let rtcp_c = graviola::aead::AesGcm::new(&rtcp_session_key);

        AesGcmCipher {
            profile,
            rtp_salt: aes_cm_key_derivation(master_key, master_salt, 0x2, 12),
            rtcp_salt: aes_cm_key_derivation(master_key, master_salt, 0x5, 12),
            rtp_c: rtp_c,
            rtcp_c: rtcp_c,
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

    fn rtcp_initialization_vector(&self, ssrc: u32, index: u32) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
        iv[8..12].copy_from_slice(&index.to_be_bytes());

        for i in 0..iv.len() {
            iv[i] ^= self.rtcp_salt[i];
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

        let (_, remaining) = slice.split_at_mut(header.len());
        let (payload, auth_tag) = remaining.split_at_mut(payload.len());

        let iv = self.rtp_initialization_vector(header, roc);
        self.rtp_c
            .encrypt(&iv, header, payload, auth_tag.try_into().unwrap());

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
        self.rtp_c
            .decrypt(
                &iv,
                header,
                &mut slice[..payload.len() - tag_size],
                &payload[payload.len() - tag_size..],
            )
            .map_err(|_| "authentication_failed".to_string())?;

        Ok(owned_binary)
    }

    fn encrypt_rtcp(&mut self, compound_packet: &[u8], index: u32) -> OwnedBinary {
        let ssrc = u32::from_be_bytes(compound_packet[4..8].try_into().unwrap());
        let size = compound_packet.len() + self.profile.tag_size() + 4;

        let mut owned_binary = OwnedBinary::new(size).unwrap();
        owned_binary.as_mut_slice()[..compound_packet.len()].copy_from_slice(compound_packet);

        let (header, remaining) = owned_binary.as_mut_slice().split_at_mut(8);
        let (plain_text, remaining) = remaining.split_at_mut(compound_packet.len() - 8);
        let (auth_tag, index_bytes) = remaining.split_at_mut(self.profile.tag_size());

        index_bytes.copy_from_slice(&index.to_be_bytes());
        index_bytes[0] |= 0x80;

        let iv = self.rtcp_initialization_vector(ssrc, index);
        let mut aad = Vec::<u8>::with_capacity(12);
        aad.extend_from_slice(&header);
        aad.extend_from_slice(&index_bytes);

        self.rtcp_c
            .encrypt(&iv, &aad, plain_text, auth_tag.try_into().unwrap());

        return owned_binary;
    }

    fn decrypt_rtcp(&mut self, compound_packet: &[u8]) -> Result<OwnedBinary, String> {
        let ssrc = u32::from_be_bytes(compound_packet[4..8].try_into().unwrap());
        let tag_size = self.profile.tag_size();
        let size = compound_packet.len() - tag_size - RTCP_INDEX_SIZE;

        let mut owned_binary = OwnedBinary::new(size).unwrap();
        owned_binary
            .as_mut_slice()
            .copy_from_slice(&compound_packet[..size]);

        let (header, cipher_text) = owned_binary.as_mut_slice().split_at_mut(8);
        let auth_tag = &compound_packet[size..size + tag_size];
        let index_bytes = &compound_packet[compound_packet.len() - RTCP_INDEX_SIZE..];

        let mut index = u32::from_be_bytes(index_bytes.try_into().unwrap());
        index &= 0x7FFFFFFF;

        let iv = self.rtcp_initialization_vector(ssrc, index);
        let mut aad = Vec::<u8>::with_capacity(12);
        aad.extend_from_slice(&header);
        aad.extend_from_slice(&index_bytes);

        self.rtcp_c
            .decrypt(&iv, &aad, cipher_text, auth_tag)
            .map_err(|_| "authentication_failed".to_string())?;

        Ok(owned_binary)
    }
}
