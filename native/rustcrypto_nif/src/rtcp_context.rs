use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;
use rustler::OwnedBinary;

use crate::{key_derivation::aes_cm_key_derivation, Aes128Ctr, HmacSha1, ProtectionProfile};

pub(crate) struct RTCPContext {
    profile: ProtectionProfile,
    session_key: Vec<u8>,
    auth_key: Vec<u8>,
    salt: Vec<u8>,
    out_ssrcs: std::collections::HashMap<u32, SsrcContext>,
}

struct SsrcContext {
    pub rtcp_index: u32,
}

impl SsrcContext {
    pub fn new() -> Self {
        SsrcContext { rtcp_index: 1 }
    }
}

impl RTCPContext {
    pub fn new(policy: &crate::SrtpPolicy) -> Self {
        let master_key = policy.master_key.as_slice();
        let master_salt = policy.master_salt.as_slice();

        return RTCPContext {
            profile: policy.rtcp_profile.into(),
            out_ssrcs: std::collections::HashMap::new(),
            session_key: aes_cm_key_derivation(master_key, master_salt, 0x3, 16),
            auth_key: aes_cm_key_derivation(master_key, master_salt, 0x4, 20),
            salt: aes_cm_key_derivation(master_key, master_salt, 0x5, 14),
        };
    }

    pub fn protect(&mut self, compound_packet: &[u8]) -> OwnedBinary {
        let (header, payload) = compound_packet.split_at(8);

        let ssrc = u32::from_be_bytes(header[4..].try_into().unwrap());
        let ctx = self
            .out_ssrcs
            .entry(ssrc)
            .or_insert_with(|| SsrcContext::new());

        let rtcp_index = ctx.rtcp_index;
        ctx.rtcp_index = rtcp_index.wrapping_add(1);
        let iv = self.generate_counter(ssrc, rtcp_index);

        let mut owned = OwnedBinary::new(header.len() + payload.len() + 14).unwrap();
        owned.as_mut_slice()[0..header.len()].copy_from_slice(header);
        owned.as_mut_slice()[header.len()..header.len() + payload.len()].copy_from_slice(payload);
        owned.as_mut_slice()[header.len() + payload.len()..header.len() + payload.len() + 4]
            .copy_from_slice(&rtcp_index.to_be_bytes());
        owned[header.len() + payload.len()] |= 0x80;

        Aes128Ctr::new(self.session_key.as_slice().into(), iv.as_slice().into())
            .apply_keystream(&mut owned.as_mut_slice()[header.len()..header.len() + payload.len()]);

        let auth_tag = &HmacSha1::new_from_slice(self.auth_key.as_slice())
            .unwrap()
            .chain_update(header)
            .chain_update(&owned.as_slice()[header.len()..header.len() + payload.len() + 4])
            .finalize()
            .into_bytes()[..10];

        owned.as_mut_slice()[header.len() + payload.len() + 4..].copy_from_slice(auth_tag);

        return owned;
    }

    pub fn unprotect(&mut self, data: &[u8]) -> Result<OwnedBinary, String> {
        let tag_size = 10;

        let authentication = HmacSha1::new_from_slice(self.auth_key.as_slice())
            .unwrap()
            .chain_update(&data[..data.len() - tag_size])
            .verify_truncated_left(&data[data.len() - tag_size..]);

        if authentication.is_err() {
            return Err("Authentication failed".to_string());
        }

        let (header, rest) = data.split_at(8);
        let (encrypted_data, rest) = rest.split_at(rest.len() - tag_size - 4);
        let ssrc = u32::from_be_bytes(header[4..].try_into().unwrap());
        let mut index = u32::from_be_bytes(rest[..4].try_into().unwrap());

        let mut owned = OwnedBinary::new(header.len() + encrypted_data.len()).unwrap();
        owned.as_mut_slice()[0..header.len()].copy_from_slice(header);
        owned.as_mut_slice()[header.len()..].copy_from_slice(encrypted_data);

        if index & 0x80000000 == 0 {
            return Ok(owned);
        }

        index &= 0x7FFFFFFF;
        let iv = self.generate_counter(ssrc, index);
        Aes128Ctr::new(self.session_key.as_slice().into(), &iv.into())
            .apply_keystream(&mut owned.as_mut_slice()[header.len()..]);

        Ok(owned)
    }

    fn generate_counter(&self, ssrc: u32, index: u32) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[4..8].copy_from_slice(&ssrc.to_be_bytes());
        iv[10..14].copy_from_slice(&index.to_be_bytes());

        for i in 0..self.salt.len() {
            iv[i] ^= self.salt[i];
        }

        iv
    }
}
