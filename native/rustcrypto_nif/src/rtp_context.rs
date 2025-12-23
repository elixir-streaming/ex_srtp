use std::{cmp::max, collections::HashMap};

use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;
use rustler::OwnedBinary;

use crate::{
    key_derivation::{aes_cm_key_derivation, generate_counter},
    Aes128Ctr, HmacSha1, ProtectionProfile, SrtpPolicy,
};

pub(crate) struct RTPContext {
    pub profile: ProtectionProfile,
    pub session_key: Vec<u8>,
    pub auth_key: Vec<u8>,
    pub salt: Vec<u8>,
    out_ssrcs: std::collections::HashMap<u32, SsrcContext>,
    in_ssrcs: std::collections::HashMap<u32, SsrcContext>,
}

#[derive(Default)]
struct SsrcContext {
    roc: u32,
    last_seq: u16,
    s_l: Option<u16>,
}

impl RTPContext {
    pub fn new(policy: &SrtpPolicy) -> Self {
        let master_key = policy.master_key.as_slice();
        let master_salt = policy.master_salt.as_slice();

        return RTPContext {
            profile: policy.rtp_profile.into(),
            out_ssrcs: HashMap::new(),
            in_ssrcs: HashMap::new(),
            session_key: aes_cm_key_derivation(master_key, master_salt, 0x0, 16),
            auth_key: aes_cm_key_derivation(master_key, master_salt, 0x1, 20),
            salt: aes_cm_key_derivation(master_key, master_salt, 0x2, 14),
        };
    }

    pub fn protect(&mut self, header: &[u8], payload: &[u8]) -> OwnedBinary {
        let header_size = header.len();
        let payload_size = payload.len();
        let tag_size = self.profile.tag_size();
        let size = header_size + payload_size + tag_size;

        let mut owned = OwnedBinary::new(size).unwrap();
        owned.as_mut_slice()[0..header_size].copy_from_slice(header);
        owned.as_mut_slice()[header_size..size - tag_size].copy_from_slice(payload);

        let ssrc = u32::from_be_bytes(header[8..12].try_into().unwrap());
        let seq = u16::from_be_bytes(header[2..4].try_into().unwrap());

        let ctx = self
            .out_ssrcs
            .entry(ssrc)
            .or_insert_with(|| SsrcContext::default());

        ctx.inc_roc(seq);

        let iv = generate_counter(ctx.roc, seq, ssrc, &self.salt);
        Aes128Ctr::new(self.session_key.as_slice().into(), iv.as_slice().into())
            .apply_keystream(&mut owned.as_mut_slice()[header_size..header_size + payload_size]);

        let roc = ctx.roc;
        let auth_tag = self.calculate_auth_tag(&[
            &header,
            &owned.as_slice()[header_size..header_size + payload_size],
            &roc.to_be_bytes(),
        ]);

        owned.as_mut_slice()[header_size + payload_size..size].copy_from_slice(auth_tag.as_slice());
        return owned;
    }

    pub fn unprotect(&mut self, header: &[u8], payload: &[u8]) -> Result<OwnedBinary, String> {
        let ssrc = u32::from_be_bytes(header[8..12].try_into().unwrap());
        let seq = u16::from_be_bytes(header[2..4].try_into().unwrap());
        let tag_size = self.profile.tag_size();

        let ctx = self
            .in_ssrcs
            .entry(ssrc)
            .or_insert_with(|| SsrcContext::default());

        let roc = ctx.estimate_roc(seq);

        // authentication
        let (encrypted_data, tag) = payload.split_at(payload.len() - tag_size);
        let expected_tag =
            self.calculate_auth_tag(&[&header[..], &encrypted_data[..], &roc.to_be_bytes()[..]]);

        if expected_tag != tag[..] {
            return Err("Authentication failed".to_string());
        }

        let mut owned = OwnedBinary::new(encrypted_data.len()).unwrap();
        owned.as_mut_slice().copy_from_slice(encrypted_data);

        // decryption
        let iv = generate_counter(roc, seq, ssrc, &self.salt);
        Aes128Ctr::new(self.session_key.as_slice().into(), iv.as_slice().into())
            .apply_keystream(&mut owned.as_mut_slice());

        Ok(owned)
    }

    pub fn index(&mut self, ssrc: u32, sequence_number: u16) -> u64 {
        match self.in_ssrcs.get_mut(&ssrc) {
            Some(ctx) => {
                let roc = ctx.estimate_roc(sequence_number);
                return ((roc as u64) << 16) | (sequence_number as u64);
            }
            None => {
                return sequence_number as u64;
            }
        }
    }

    fn calculate_auth_tag(&self, data: &[&[u8]]) -> Vec<u8> {
        let mut mac = HmacSha1::new_from_slice(self.auth_key.as_slice()).unwrap();
        for chunk in data {
            mac.update(chunk);
        }
        return mac.finalize().into_bytes()[0..self.profile.tag_size()].to_vec();
    }
}

impl SsrcContext {
    pub fn inc_roc(&mut self, seq: u16) {
        if seq < self.last_seq {
            self.roc = self.roc.wrapping_add(1);
        }
        self.last_seq = seq;
    }

    pub fn estimate_roc(&mut self, seq_number: u16) -> u32 {
        let s_l = match self.s_l {
            Some(s_l) => s_l,
            None => {
                self.s_l = Some(seq_number);
                return self.roc;
            }
        };

        let mut roc = self.roc;

        if s_l < 32_768 {
            if seq_number as i32 - s_l as i32 > 32_768 {
                roc = roc.wrapping_sub(1);
            } else {
                self.s_l = Some(max(s_l, seq_number));
            }
        } else {
            if s_l as i32 - 32_768 as i32 > seq_number as i32 {
                roc = roc.wrapping_add(1);
                self.roc = roc;
                self.s_l = Some(seq_number);
            } else {
                self.s_l = Some(max(s_l, seq_number));
            }
        }

        return roc;
    }
}
