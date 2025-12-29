use std::vec;

use aes::cipher::{KeyIvInit, StreamCipher};

use crate::Aes128Ctr;

pub(crate) fn aes_cm_key_derivation(
    master_key: &[u8],
    master_salt: &[u8],
    label: u8,
    out_length: usize,
) -> Vec<u8> {
    let mut iv = vec![0u8; master_key.len()];
    let mut out = vec![0u8; out_length];

    iv[0..master_salt.len()].copy_from_slice(master_salt);
    iv[7] ^= label;

    Aes128Ctr::new(master_key.into(), iv.as_slice().into()).apply_keystream(out.as_mut_slice());
    return out;
}

pub(crate) fn generate_counter(roc: u32, seq_number: u16, ssrc: u32, salt: &[u8]) -> [u8; 16] {
    let mut counter = [0; 16];

    let ssrc_be = ssrc.to_be_bytes();
    let roc_be = roc.to_be_bytes();
    let seq_be = ((seq_number as u32) << 16).to_be_bytes();

    counter[4..8].copy_from_slice(&ssrc_be);
    counter[8..12].copy_from_slice(&roc_be);
    counter[12..16].copy_from_slice(&seq_be);

    for i in 0..salt.len() {
        counter[i] ^= salt[i];
    }

    counter
}
