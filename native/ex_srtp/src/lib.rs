use std::{collections::HashMap, sync::Mutex};

use hmac::Hmac;
use rustler::{Atom, Binary, Env, NifStruct, Resource, ResourceArc, Term};

use crate::{
    cipher::Cipher,
    rtp_context::{RTCPContext, RTPContext},
};

pub mod cipher;
pub mod key_derivation;
pub mod protection_profile;
pub mod rtp_context;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
type HmacSha1 = Hmac<sha1::Sha1>;

struct Session {
    cipher: Box<dyn Cipher + Send>,
    in_rtp_ctx: HashMap<u32, RTPContext>,
    out_rtp_ctx: HashMap<u32, RTPContext>,
    out_rtcp_ctx: HashMap<u32, RTCPContext>,
}

struct State {
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
        session: Mutex::new(Session {
            cipher: cipher::create_cipher(&policy),
            in_rtp_ctx: HashMap::new(),
            out_rtp_ctx: HashMap::new(),
            out_rtcp_ctx: HashMap::new(),
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
    let mut session = state.session.lock().unwrap();
    let ssrc = u32::from_be_bytes(data.as_slice()[4..8].try_into().unwrap());
    let ctx = session
        .out_rtcp_ctx
        .entry(ssrc)
        .or_insert_with(|| RTCPContext { index: 0 });

    ctx.index = ctx.index.wrapping_add(1);
    let rtcp_index = ctx.index;
    return Binary::from_owned(session.cipher.encrypt_rtcp(&data, rtcp_index), env);
}

#[rustler::nif]
fn unprotect<'a>(
    env: Env<'a>,
    state: ResourceArc<State>,
    header: Binary<'a>,
    payload: Binary<'a>,
) -> Result<Binary<'a>, Atom> {
    let mut session = state.session.lock().unwrap();
    let ssrc = u32::from_be_bytes(header.as_slice()[8..12].try_into().unwrap());
    let seq = u16::from_be_bytes(header.as_slice()[2..4].try_into().unwrap());

    let ctx = session
        .in_rtp_ctx
        .entry(ssrc)
        .or_insert_with(|| RTPContext::default());

    let roc = ctx.estimate_roc(seq);
    match session
        .cipher
        .decrypt_rtp(&header.as_slice(), &payload.as_slice(), roc)
    {
        Err(err) => Err(Atom::from_str(env, err.as_str()).unwrap()),
        Ok(owned) => {
            session.in_rtp_ctx.get_mut(&ssrc).unwrap().update_roc(seq);
            Ok(Binary::from_owned(owned, env))
        }
    }
}

#[rustler::nif]
fn unprotect_rtcp<'a>(
    env: Env<'a>,
    state: ResourceArc<State>,
    data: Binary<'a>,
) -> Result<Binary<'a>, Atom> {
    let mut session = state.session.lock().unwrap();
    match session.cipher.decrypt_rtcp(&data.as_slice()) {
        Err(err) => return Err(Atom::from_str(env, err.as_str()).unwrap()),
        Ok(owned) => Ok(Binary::from_owned(owned, env)),
    }
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
