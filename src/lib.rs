#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate failure;

use base64::encode as base64_encode;
use num_enum::TryFromPrimitive;
use serde_json::Value;

use std::convert::TryFrom;
use std::convert::TryInto;

lazy_static! {
    static ref CURVE25519: () = {};
}

pub const MIN_SUPPORTED_VERSION: u8 = 0;
pub const MAX_SUPPORTED_VERSION: u8 = 0;

pub const MAGIC_BWT: [u8; 4] = [66, 87, 84, 0];

pub const MAX_TOKEN_CHARS: usize = 4096;

pub const SECRET_KEY_BYTES: usize = 32;

pub const PUBLIC_KEY_BYTES: usize = 32;

pub const KID_BYTES: usize = 16;

pub const BASE64_KID_CHARS: usize = 24;

pub const HEADER_BYTES: usize = 48;

#[derive(Fail, Debug)]
pub enum BWTError {
    #[fail(display = "{} is not a valid BWT version.", _0)]
    UnsupportedVersion(u8),
    #[fail(display = "Invalid header bytes: {}", _0)]
    InvalidHeaderBytes(usize),
    #[fail(display = "Invalid magic bytes")]
    InvalidMagicBytes,
    #[fail(display = "An unknown error has occurred.")]
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum Typ {
    BWTv0,
}

#[derive(Clone, Debug)]
pub struct Header {
    typ: Typ,
    iat: u64,
    exp: u64,
    kid: [u8; KID_BYTES],
}

#[derive(Clone, Debug)]
pub struct Contents {
    header: Header,
    body: Value,
}

#[derive(Clone, Debug)]
pub struct KeyPair {
    secret_key: [u8; SECRET_KEY_BYTES],
    public_key: [u8; PUBLIC_KEY_BYTES],
    kid: [u8; KID_BYTES],
}

#[derive(Clone, Debug)]
pub struct PeerPublicKey {
    public_key: [u8; PUBLIC_KEY_BYTES],
    kid: [u8; KID_BYTES],
}

#[derive(Clone, Debug)]
pub struct InternalPeerPublicKey {
    public_key: [u8; PUBLIC_KEY_BYTES],
    base64_kid: String,
}

#[derive(Clone, Debug)]
pub struct InternalHeader {
    typ: Typ,
    iat: u64,
    exp: u64,
    kid: [u8; KID_BYTES],
    nonce: [u8; 12],
    base64_kid: String,
}

// CLARIFY: does .unwrap() bubble errors down the stack or it just panics?

fn try_derive_typ(buf: &[u8]) -> Result<Typ, BWTError> {
    let version: u8 = buf[4];

    let mut diff: u8 = 0;

    for i in 0..4 {
        diff |= buf[i] ^ MAGIC_BWT[i];
    }

    if diff != 0 {
        Err(BWTError::InvalidMagicBytes)
    } else if version < MIN_SUPPORTED_VERSION || version > MAX_SUPPORTED_VERSION {
        Err(BWTError::UnsupportedVersion(version))
    } else {
        Ok(Typ::try_from(version).unwrap())
    }
}

impl InternalHeader {
    fn from_buffer(buf: &[u8]) -> Result<InternalHeader, BWTError> {
        if buf.len() < HEADER_BYTES {
            Err(BWTError::InvalidHeaderBytes(buf.len()))
        } else {
            Ok(InternalHeader {
                typ: try_derive_typ(buf)?,
                iat: u64::from_be_bytes(buf[4..12].try_into().unwrap()),
                exp: u64::from_be_bytes(buf[12..20].try_into().unwrap()),
                kid: buf[20..36].try_into().unwrap(),
                nonce: buf[36..48].try_into().unwrap(),
                base64_kid: base64_encode(&buf[20..36]).to_string(),
            })
        }
    }

    fn from_header_and_nonce(header: &Header, nonce: &[u8]) -> Result<InternalHeader, BWTError> {
        Ok(InternalHeader {
            typ: header.typ.clone(),
            iat: header.iat,
            exp: header.exp,
            kid: header.kid,
            nonce: nonce.try_into().unwrap(),
            base64_kid: base64_encode(&header.kid).to_string(),
        })
    }

    fn to_buffer(self: &InternalHeader, buf: &mut [u8]) -> Result<(), BWTError> {
        buf[0..4].copy_from_slice(&MAGIC_BWT);
        buf[4..12].copy_from_slice(&self.iat.to_be_bytes());
        buf[12..20].copy_from_slice(&self.exp.to_be_bytes());
        buf[20..36].copy_from_slice(&self.kid);
        buf[36..48].copy_from_slice(&self.nonce);

        Ok(())
    }

    fn to_header(self: &InternalHeader) -> Result<Header, BWTError> {
        Ok(Header {
            typ: self.typ.clone(),
            iat: self.iat,
            exp: self.exp,
            kid: self.kid.try_into().unwrap(),
        })
    }
}

// /** Creates a nonce generator that is based on the current timestamp. */
// function* createNonceGenerator(): Generator {
//   let base: bigint = BigInt(String(Date.now()).slice(-NONCE_BYTES));
//
//   for (;;) {
//     yield encode(String(++base), "utf8");
//   }
// }
//
// /** Transforms a collection of public keys to a map representation. */
// function toPublicKeyMap(
//   ...peerPublicKeys: PeerPublicKey[]
// ): Map<string, Uint8Array> {
//   const map: Map<string, Uint8Array> = new Map<string, Uint8Array>();
//
//   for (const peerPublicKey of peerPublicKeys) {
//     map.set(peerPublicKey.kid as string, peerPublicKey.publicKey as Uint8Array);
//   }
//
//   return map;
// }
//
// /** Concatenates aad, ciphertext, and tag to a token. */
// function assembleToken(
//   aad: Uint8Array,
//   ciphertext: Uint8Array,
//   tag: Uint8Array
// ): string {
//   return (
//     decode(aad, "base64") +
//     "." +
//     decode(ciphertext, "base64") +
//     "." +
//     decode(tag, "base64")
//   );
// }
//
// /** Whether given input is a valid BWT header object. */
// function isValidHeader(x: any): boolean {
//   const now: number = Date.now();
//   return (
//     x &&
//     SUPPORTED_VERSIONS.has(x.typ) &&
//     x.kid &&
//     x.kid.length === BASE64_KID_CHARS &&
//     x.iat >= 0 &&
//     x.iat % 1 === 0 &&
//     x.iat <= now &&
//     x.exp >= 0 &&
//     x.exp % 1 === 0 &&
//     x.exp > now
//   );
// }
//
// /** Whether given input is a valid BWT secret key. */
// function isValidSecretKey(x: Uint8Array): boolean {
//   return x && x.byteLength === SECRET_KEY_BYTES;
// }
//
// /**
//  *  Whether given input is a valid BWT peer public key.
//  *
//  * This function must be passed normalized peer public keys as it assumes a
//  * buffer publicKey prop for the byte length check.
//  */
// function isValidPeerPublicKey(x: PeerPublicKey): boolean {
//   return (
//     x &&
//     x.kid &&
//     x.kid.length === BASE64_KID_CHARS &&
//     x.publicKey.length === PUBLIC_KEY_BYTES
//   );
// }
//
// /** Whether given input string has a valid token size. */
// function hasValidTokenSize(x: string): boolean {
//   return x && x.length <= MAX_TOKEN_CHARS;
// }
//
// /** Efficiently derives a shared key from recurring kid strings. */
// function deriveSharedKeyProto(
//   secretKey: Uint8Array,
//   sharedKeyCache: Map<string, Uint8Array>,
//   defaultPublicKeyMap: Map<string, Uint8Array>,
//   defaultKid: string,
//   kid: string = defaultKid,
//   ...peerPublicKeySpace: PeerPublicKey[]
// ): Uint8Array {
//   if (sharedKeyCache.has(kid)) {
//     return sharedKeyCache.get(kid);
//   }
//
//   let publicKey: Uint8Array;
//
//   if (peerPublicKeySpace.length) {
//     let peerPublicKey: PeerPublicKey = peerPublicKeySpace.find(
//       ({ kid: _kid }: PeerPublicKey): boolean => _kid === kid
//     );
//
//     publicKey = peerPublicKey ? (peerPublicKey.publicKey as Uint8Array) : null;
//   } else if (defaultPublicKeyMap.has(kid)) {
//     publicKey = defaultPublicKeyMap.get(kid);
//   }
//
//   if (!publicKey) {
//     return null;
//   }
//
//   const sharedKey: Uint8Array = CURVE25519.scalarMult(secretKey, publicKey);
//
//   sharedKeyCache.set(kid, sharedKey);
//
//   return sharedKey;
// }

#[cfg(test)]
mod tests;
