use std::{collections::HashMap, sync::Mutex};

use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use rustler::{Atom, Binary, Env, NifStruct, OwnedBinary, Resource, ResourceArc, Term};

use crate::context::Context;

pub mod context;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
type HmacSha1 = Hmac<sha1::Sha1>;

struct CryptoContext {
    pub rtp_profile: Atom,
    pub rtcp_profile: Atom,
    pub rtp_session_key: [u8; 16],
    pub rtp_auth_key: [u8; 20],
    pub rtp_salt: [u8; 14],
    pub rtcp_session_key: [u8; 16],
    pub rtcp_auth_key: [u8; 20],
    pub rtcp_salt: [u8; 14],
    pub contexts: HashMap<u32, Context>,
}

impl CryptoContext {
    pub fn new(policy: SrtpPolicy) -> Self {
        let mut context = CryptoContext {
            rtp_profile: policy.rtp_profile,
            rtcp_profile: policy.rtcp_profile,
            contexts: HashMap::new(),
            rtp_session_key: [0u8; 16],
            rtp_auth_key: [0u8; 20],
            rtp_salt: [0u8; 14],
            rtcp_session_key: [0u8; 16],
            rtcp_auth_key: [0u8; 20],
            rtcp_salt: [0u8; 14],
        };

        context.derive_rtp_keys(policy.master_key.as_slice(), policy.master_salt.as_slice());
        context.derive_rtcp_keys(policy.master_key.as_slice(), policy.master_salt.as_slice());
        return context;
    }

    pub fn encrypt_rtp(&mut self, header: &[u8], payload: &[u8]) -> OwnedBinary {
        let header_size = header.len();
        let payload_size = payload.len();
        let size = header_size + payload_size + 10;

        let mut owned = OwnedBinary::new(size).unwrap();
        owned.as_mut_slice()[0..header_size].copy_from_slice(header);
        owned.as_mut_slice()[header_size..size - 10].copy_from_slice(payload);

        let ssrc = u32::from_be_bytes(header[8..12].try_into().unwrap());
        let seq = u16::from_be_bytes(header[2..4].try_into().unwrap());

        let ctx = self.contexts.entry(ssrc).or_insert_with(|| {
            Context::new(ssrc, &self.rtp_salt.as_slice(), &self.rtcp_salt.as_slice())
        });

        ctx.inc_roc(seq);

        Aes128Ctr::new(
            self.rtp_session_key.as_slice().into(),
            ctx.iv(header).into(),
        )
        .apply_keystream(&mut owned.as_mut_slice()[header_size..header_size + payload_size]);

        let mut mac = HmacSha1::new_from_slice(self.rtp_auth_key.as_slice())
            .expect("HMAC can take key of any size");
        mac.update(header);
        mac.update(&owned.as_slice()[header_size..header_size + payload_size]);
        mac.update(ctx.roc.to_be_bytes().as_ref());

        owned.as_mut_slice()[header_size + payload_size..size]
            .copy_from_slice(&mac.finalize().into_bytes()[..10]);

        return owned;
    }

    pub fn encrypt_rtcp(&mut self, compound_packet: &[u8]) -> OwnedBinary {
        let (header, payload) = compound_packet.split_at(8);

        let ssrc = u32::from_be_bytes(header[4..].try_into().unwrap());
        let ctx = self.contexts.entry(ssrc).or_insert_with(|| {
            Context::new(ssrc, &self.rtp_salt.as_slice(), &self.rtcp_salt.as_slice())
        });

        let mut index_bytes = ctx.rtcp_index.to_be_bytes();
        index_bytes[0] |= 0x80;

        let mut owned = OwnedBinary::new(header.len() + payload.len() + 14).unwrap();
        owned.as_mut_slice()[0..header.len()].copy_from_slice(header);
        owned.as_mut_slice()[header.len()..header.len() + payload.len()].copy_from_slice(payload);
        owned.as_mut_slice()[header.len() + payload.len()..header.len() + payload.len() + 4]
            .copy_from_slice(&index_bytes);

        Aes128Ctr::new(
            self.rtcp_session_key.as_slice().into(),
            ctx.rtcp_iv().into(),
        )
        .apply_keystream(&mut owned.as_mut_slice()[header.len()..header.len() + payload.len()]);

        let mut mac = HmacSha1::new_from_slice(self.rtcp_auth_key.as_slice())
            .expect("HMAC can take key of any size");
        mac.update(header);
        mac.update(&owned.as_slice()[header.len()..header.len() + payload.len() + 4]);

        owned.as_mut_slice()[header.len() + payload.len() + 4..]
            .copy_from_slice(&mac.finalize().into_bytes()[..10]);

        ctx.rtcp_index = ctx.rtcp_index.wrapping_add(1);

        return owned;
    }

    fn derive_rtp_keys(&mut self, master_key: &[u8], master_salt: &[u8]) {
        let mut session_iv = [0u8; 16];
        let mut auth_iv = [0u8; 16];
        let mut salt_iv = [0u8; 16];

        session_iv.as_mut_slice()[0..14].copy_from_slice(master_salt);
        auth_iv.as_mut_slice()[0..14].copy_from_slice(master_salt);
        salt_iv.as_mut_slice()[0..14].copy_from_slice(master_salt);

        auth_iv[7] ^= 0x01;
        salt_iv[7] ^= 0x02;

        let mut cipher = Aes128Ctr::new(master_key.into(), &session_iv.into());
        cipher.apply_keystream(&mut self.rtp_session_key);

        let mut cipher = Aes128Ctr::new(master_key.into(), &auth_iv.into());
        cipher.apply_keystream(&mut self.rtp_auth_key);

        let mut cipher = Aes128Ctr::new(master_key.into(), &salt_iv.into());
        cipher.apply_keystream(&mut self.rtp_salt);
    }

    fn derive_rtcp_keys(&mut self, master_key: &[u8], master_salt: &[u8]) {
        let mut session_iv = [0u8; 16];
        let mut auth_iv = [0u8; 16];
        let mut salt_iv = [0u8; 16];

        session_iv.as_mut_slice()[0..14].copy_from_slice(master_salt);
        auth_iv.as_mut_slice()[0..14].copy_from_slice(master_salt);
        salt_iv.as_mut_slice()[0..14].copy_from_slice(master_salt);

        session_iv[7] ^= 0x03;
        auth_iv[7] ^= 0x04;
        salt_iv[7] ^= 0x05;

        let mut cipher = Aes128Ctr::new(master_key.into(), &session_iv.into());
        cipher.apply_keystream(&mut self.rtcp_session_key);

        let mut cipher = Aes128Ctr::new(master_key.into(), &auth_iv.into());
        cipher.apply_keystream(&mut self.rtcp_auth_key);

        let mut cipher = Aes128Ctr::new(master_key.into(), &salt_iv.into());
        cipher.apply_keystream(&mut self.rtcp_salt);
    }
}

struct State {
    crypto_context: Mutex<CryptoContext>,
}

impl Resource for State {}

#[derive(NifStruct)]
#[module = "ExSRTP.Policy"]
struct SrtpPolicy<'a> {
    pub master_key: Binary<'a>,
    pub master_salt: Binary<'a>,
    pub rtp_profile: Atom,
    pub rtcp_profile: Atom,
}

fn load(env: Env, _: Term) -> bool {
    env.register::<State>().is_ok()
}

#[rustler::nif]
fn init(policy: SrtpPolicy) -> ResourceArc<State> {
    ResourceArc::new(State {
        crypto_context: Mutex::new(CryptoContext::new(policy)),
    })
}

#[rustler::nif]
fn protect<'a>(
    env: Env<'a>,
    state: ResourceArc<State>,
    header: Binary<'a>,
    payload: Binary<'a>,
) -> Binary<'a> {
    let owned = state
        .crypto_context
        .lock()
        .unwrap()
        .encrypt_rtp(&header.as_slice(), &payload.as_slice());

    return Binary::from_owned(owned, env);
}

#[rustler::nif]
fn protect_rtcp<'a>(env: Env<'a>, state: ResourceArc<State>, data: Binary<'a>) -> Binary<'a> {
    let owned = state
        .crypto_context
        .lock()
        .unwrap()
        .encrypt_rtcp(&data.as_slice());

    return Binary::from_owned(owned, env);
}

rustler::init!("Elixir.ExSRTP.Backend.RustCrypto.Native", load = load);
