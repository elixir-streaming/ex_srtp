use std::{collections::HashMap, sync::Mutex};

use hmac::Hmac;
use rustler::{atoms, Atom, Binary, Env, NifStruct, Resource, ResourceArc, Term};

use crate::{cipher::Cipher, rtcp_context::RTCPContext, rtp_context::RTPContext};

pub mod cipher;
pub mod key_derivation;
pub mod protection_profile;
pub mod rtcp_context;
pub mod rtp_context;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
type HmacSha1 = Hmac<sha1::Sha1>;

atoms! {
    aes_cm_128_hmac_sha1_80,
    aes_cm_128_hmac_sha1_32,
}

struct Session {
    cipher: Box<dyn Cipher + Send>,
    in_rtp_ctx: HashMap<u32, RTPContext>,
    out_rtp_ctx: HashMap<u32, RTPContext>,
}

struct State {
    rtcp_context: Mutex<RTCPContext>,
    session: Mutex<Session>,
}

impl Resource for State {}

#[derive(NifStruct)]
#[module = "ExSRTP.Policy"]
struct SrtpPolicy<'a> {
    pub master_key: Binary<'a>,
    pub master_salt: Binary<'a>,
    pub profile: Atom,
}

fn load(env: Env, _: Term) -> bool {
    env.register::<State>().is_ok()
}

#[rustler::nif]
fn init(policy: SrtpPolicy) -> ResourceArc<State> {
    ResourceArc::new(State {
        rtcp_context: Mutex::new(RTCPContext::new(&policy)),
        session: Mutex::new(Session {
            cipher: cipher::create_cipher(&policy),
            in_rtp_ctx: HashMap::new(),
            out_rtp_ctx: HashMap::new(),
        }),
    })
}

#[rustler::nif]
fn protect<'a>(
    env: Env<'a>,
    state: ResourceArc<State>,
    header: Binary<'a>,
    payload: Binary<'a>,
) -> Binary<'a> {
    let mut session = state.session.lock().unwrap();
    let ssrc = u32::from_be_bytes(header.as_slice()[8..12].try_into().unwrap());
    let seq = u16::from_be_bytes(header.as_slice()[2..4].try_into().unwrap());

    let ctx = session
        .out_rtp_ctx
        .entry(ssrc)
        .or_insert_with(|| RTPContext::default());

    let roc = ctx.inc_roc(seq);

    let owned = session
        .cipher
        .encrypt_rtp(&header.as_slice(), &payload.as_slice(), roc);

    return Binary::from_owned(owned, env);
}

#[rustler::nif]
fn protect_rtcp<'a>(env: Env<'a>, state: ResourceArc<State>, data: Binary<'a>) -> Binary<'a> {
    let owned = state.rtcp_context.lock().unwrap().protect(&data.as_slice());
    return Binary::from_owned(owned, env);
}

#[rustler::nif]
fn unprotect<'a>(
    env: Env<'a>,
    state: ResourceArc<State>,
    header: Binary<'a>,
    payload: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let mut session = state.session.lock().unwrap();
    let ssrc = u32::from_be_bytes(header.as_slice()[8..12].try_into().unwrap());
    let seq = u16::from_be_bytes(header.as_slice()[2..4].try_into().unwrap());

    let ctx = session
        .in_rtp_ctx
        .entry(ssrc)
        .or_insert_with(|| RTPContext::default());

    let roc = ctx.estimate_roc(seq);

    let owned = session
        .cipher
        .decrypt_rtp(&header.as_slice(), &payload.as_slice(), roc)?;

    session.in_rtp_ctx.get_mut(&ssrc).unwrap().update_roc(seq);

    // let owned = state
    //     .rtp_context
    //     .lock()
    //     .unwrap()
    //     .unprotect(&header.as_slice(), &payload.as_slice())
    //     .map_err(|e| e.to_string())?;

    return Ok(Binary::from_owned(owned, env));
}

#[rustler::nif]
fn unprotect_rtcp<'a>(
    env: Env<'a>,
    state: ResourceArc<State>,
    data: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let owned = state
        .rtcp_context
        .lock()
        .unwrap()
        .unprotect(&data.as_slice())
        .map_err(|e| e.to_string())?;

    return Ok(Binary::from_owned(owned, env));
}

#[rustler::nif]
fn rtp_index(state: ResourceArc<State>, ssrc: u32, sequence_number: u16) -> u64 {
    let session = state.session.lock().unwrap();
    return session.in_rtp_ctx.get(&ssrc).map_or_else(
        || sequence_number as u64,
        |ctx| {
            let roc = ctx.estimate_roc(sequence_number);
            (roc as u64) << 16 | (sequence_number as u64)
        },
    );
}

rustler::init!("Elixir.ExSRTP.Backend.RustCrypto.Native", load = load);
