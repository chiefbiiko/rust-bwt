#[macro_use]
extern crate lazy_static;

use serde_json::Value;
use std::collections::HashSet;
use std::str::from_utf8;
use std::convert::TryInto;

lazy_static! {
    static ref MAGIC_BWT: Vec<u8> = vec![66, 87, 84, 0];

    static ref SUPPORTED_VERSIONS: HashSet<&'static str> = {
        let mut set: HashSet<&'static str> = HashSet::new();
        set.insert("BWTv0");
        set
    };

    // TODO
    static ref CURVE25519: () = {};
}

const MAX_TOKEN_CHARS: usize = 4096;

const SECRET_KEY_BYTES: usize = 32;

const PUBLIC_KEY_BYTES: usize = 32;

const BASE64_KID_CHARS: usize = 24;

const HEADER_BYTES: usize = 48;

// TODO: Have all structs own their fields!

#[derive(Debug)]
struct Header<'a> {
    typ: &'a str,
    iat: u64,
    exp: u64,
    kid: &'a [u8],
}

#[derive(Debug)]
struct Contents<'a, 'b: 'a> {
    header: &'a Header<'b>,
    body: &'a Value,
}

#[derive(Debug)]
struct KeyPair<'a> {
    secret_key: &'a [u8],
    public_key: &'a [u8],
    kid: &'a [u8],
}

#[derive(Debug)]
struct PeerPublicKey<'a> {
    public_key: &'a [u8],
    kid: &'a [u8],
}

#[derive(Debug)]
struct InternalHeader<'a> {
    header: &'a Header<'a>,
    nonce: &'a [u8],
}

fn internal_header_to_buffer(internal_header: &InternalHeader) -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; HEADER_BYTES];

    buf[0..4].copy_from_slice(&MAGIC_BWT);
    buf[4..12].copy_from_slice(&internal_header.header.iat.to_be_bytes());
    buf[12..20].copy_from_slice(&internal_header.header.exp.to_be_bytes());
    buf[20..36].copy_from_slice(&internal_header.header.kid);
    buf[36..48].copy_from_slice(&internal_header.nonce);

    buf
}

fn buffer_to_internal_header(buf: &[u8]) -> InternalHeader {
    InternalHeader {
        header: &Header {
typ: format!("{}{}",from_utf8(&buf[0..3]).unwrap(),u8::from_be_bytes(buf[4..4].try_into().unwrap())).as_ref(),
iat: u64::from_be_bytes(buf[4..12].try_into().unwrap()),
exp: u64::from_be_bytes(buf[12..20].try_into().unwrap()),
kid: &buf[20..36],
        },
        nonce: &buf[36..48],
    }
}

#[cfg(test)]
mod tests;
