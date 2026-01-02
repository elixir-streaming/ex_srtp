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
