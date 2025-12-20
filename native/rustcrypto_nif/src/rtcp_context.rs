use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;
use rustler::{Atom, OwnedBinary};

use crate::{key_derivation::aes_cm_key_derivation, Aes128Ctr, HmacSha1};

pub(crate) struct RTCPContext {
    pub profile: Atom,
    pub session_key: Vec<u8>,
    pub auth_key: Vec<u8>,
    pub salt: Vec<u8>,
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
            profile: policy.rtcp_profile,
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

        let mut index_bytes = ctx.rtcp_index.to_be_bytes();
        let mut iv = vec![0u8; 16];

        iv[0..self.salt.len()].copy_from_slice(&self.salt);
        for i in 0..4 {
            iv[i + 4] ^= header[4 + i];
            iv[i + 10] ^= index_bytes[i];
        }

        index_bytes[0] |= 0x80;

        let mut owned = OwnedBinary::new(header.len() + payload.len() + 14).unwrap();
        owned.as_mut_slice()[0..header.len()].copy_from_slice(header);
        owned.as_mut_slice()[header.len()..header.len() + payload.len()].copy_from_slice(payload);
        owned.as_mut_slice()[header.len() + payload.len()..header.len() + payload.len() + 4]
            .copy_from_slice(&index_bytes);

        Aes128Ctr::new(self.session_key.as_slice().into(), iv.as_slice().into())
            .apply_keystream(&mut owned.as_mut_slice()[header.len()..header.len() + payload.len()]);

        let mut mac = HmacSha1::new_from_slice(self.auth_key.as_slice())
            .expect("HMAC can take key of any size");
        mac.update(header);
        mac.update(&owned.as_slice()[header.len()..header.len() + payload.len() + 4]);

        owned.as_mut_slice()[header.len() + payload.len() + 4..]
            .copy_from_slice(&mac.finalize().into_bytes()[..10]);

        ctx.rtcp_index = ctx.rtcp_index.wrapping_add(1);

        return owned;
    }
}
