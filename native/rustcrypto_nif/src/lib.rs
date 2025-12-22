use core::panic;
use std::sync::Mutex;

use hmac::Hmac;
use rustler::{atoms, Atom, Binary, Env, NifStruct, Resource, ResourceArc, Term};

use crate::{rtcp_context::RTCPContext, rtp_context::RTPContext};

pub mod key_derivation;
pub mod rtcp_context;
pub mod rtp_context;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
type HmacSha1 = Hmac<sha1::Sha1>;

atoms! {
    aes_cm_128_hmac_sha1_80,
    aes_cm_128_hmac_sha1_32,
}

#[derive(Debug)]
enum ProtectionProfile {
    AesCm128HmacSha1_80,
    AesCm128HmacSha1_32,
}

impl From<Atom> for ProtectionProfile {
    fn from(atom: Atom) -> Self {
        match atom {
            atom if aes_cm_128_hmac_sha1_80() == atom => ProtectionProfile::AesCm128HmacSha1_80,
            atom if aes_cm_128_hmac_sha1_32() == atom => ProtectionProfile::AesCm128HmacSha1_32,
            _ => panic!("Unsupported protection profile"),
        }
    }
}

impl ProtectionProfile {
    fn tag_size(&self) -> usize {
        match self {
            ProtectionProfile::AesCm128HmacSha1_80 => 10,
            ProtectionProfile::AesCm128HmacSha1_32 => 4,
        }
    }
}

struct State {
    rtp_context: Mutex<RTPContext>,
    rtcp_context: Mutex<RTCPContext>,
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
        rtp_context: Mutex::new(RTPContext::new(&policy)),
        rtcp_context: Mutex::new(RTCPContext::new(&policy)),
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
        .rtp_context
        .lock()
        .unwrap()
        .protect(&header.as_slice(), &payload.as_slice());

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
    let owned = state
        .rtp_context
        .lock()
        .unwrap()
        .unprotect(&header.as_slice(), &payload.as_slice())
        .map_err(|e| e.to_string())?;

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

rustler::init!("Elixir.ExSRTP.Backend.RustCrypto.Native", load = load);
