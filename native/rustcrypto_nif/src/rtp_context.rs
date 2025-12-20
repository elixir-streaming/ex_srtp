use std::collections::HashMap;

use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;
use rustler::{Atom, OwnedBinary};

use crate::{key_derivation::aes_cm_key_derivation, Aes128Ctr, HmacSha1, SrtpPolicy};

pub(crate) struct RTPContext {
    pub profile: Atom,
    pub session_key: Vec<u8>,
    pub auth_key: Vec<u8>,
    pub salt: Vec<u8>,
    out_ssrcs: std::collections::HashMap<u32, SsrcContext>,
}

struct SsrcContext {
    pub roc: u32,
    pub last_seq: u16,
}

impl RTPContext {
    pub fn new(policy: &SrtpPolicy) -> Self {
        let master_key = policy.master_key.as_slice();
        let master_salt = policy.master_salt.as_slice();

        return RTPContext {
            profile: policy.rtp_profile,
            out_ssrcs: HashMap::new(),
            session_key: aes_cm_key_derivation(master_key, master_salt, 0x0, 16),
            auth_key: aes_cm_key_derivation(master_key, master_salt, 0x1, 20),
            salt: aes_cm_key_derivation(master_key, master_salt, 0x2, 14),
        };
    }

    pub fn protect(&mut self, header: &[u8], payload: &[u8]) -> OwnedBinary {
        let header_size = header.len();
        let payload_size = payload.len();
        let size = header_size + payload_size + 10;

        let mut owned = OwnedBinary::new(size).unwrap();
        owned.as_mut_slice()[0..header_size].copy_from_slice(header);
        owned.as_mut_slice()[header_size..size - 10].copy_from_slice(payload);

        let ssrc = u32::from_be_bytes(header[8..12].try_into().unwrap());
        let seq = u16::from_be_bytes(header[2..4].try_into().unwrap());

        let ctx = self
            .out_ssrcs
            .entry(ssrc)
            .or_insert_with(|| SsrcContext::new());

        ctx.inc_roc(seq);

        let mut iv = vec![0u8; 16];
        let index_bytes = ctx.index(seq).to_be_bytes();

        iv[0..self.salt.len()].copy_from_slice(&self.salt);
        for i in 0..4 {
            iv[i + 4] ^= header[8 + i];
        }
        for i in 0..6 {
            iv[i + 8] ^= index_bytes[i + 2];
        }

        Aes128Ctr::new(self.session_key.as_slice().into(), iv.as_slice().into())
            .apply_keystream(&mut owned.as_mut_slice()[header_size..header_size + payload_size]);

        let mut mac = HmacSha1::new_from_slice(self.auth_key.as_slice()).unwrap();
        mac.update(header);
        mac.update(&owned.as_slice()[header_size..header_size + payload_size]);
        mac.update(ctx.roc.to_be_bytes().as_ref());

        owned.as_mut_slice()[header_size + payload_size..size]
            .copy_from_slice(&mac.finalize().into_bytes()[..10]);

        return owned;
    }
}

impl SsrcContext {
    pub fn new() -> Self {
        return SsrcContext {
            roc: 0,
            last_seq: 0,
        };
    }

    pub fn inc_roc(&mut self, seq: u16) {
        if seq < self.last_seq {
            self.roc = self.roc.wrapping_add(1);
        }
        self.last_seq = seq;
    }

    pub fn index(&self, seq_number: u16) -> u64 {
        return (self.roc as u64) << 16 | (seq_number as u64);
    }
}
