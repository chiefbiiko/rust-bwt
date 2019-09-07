// #[macro_use]
// extern crate lazy_static;

use base64::encode as base64_encode;
use num_enum::{IntoPrimitive, TryFromPrimitive, TryFromPrimitiveError};
use serde_json::Value;

use std::collections::HashMap;
use std::convert::{From, TryFrom, TryInto};
use std::error::Error;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use core::array::TryFromSliceError;

// lazy_static! {
//     static ref CURVE25519: () = {};
// }

pub const MIN_SUPPORTED_VERSION: u8 = 0;
pub const MAX_SUPPORTED_VERSION: u8 = 0;
pub const MAGIC_BWT: [u8; 3] = [66, 87, 84];
pub const MAX_TOKEN_CHARS: usize = 4096;
pub const SECRET_KEY_BYTES: usize = 32;
pub const PUBLIC_KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const KID_BYTES: usize = 16;
pub const BASE64_KID_CHARS: usize = 24;
pub const HEADER_BYTES: usize = 48;

#[derive(Debug)]
pub enum BWTError {
    InvalidMagicBytes,
    InvalidHeaderBytes(usize),
    UnsupportedVersion(u8),
    Other(Box<dyn Error>),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
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
    nonce: [u8; NONCE_BYTES],
    base64_kid: String,
}

#[derive(Clone, Debug)]
struct PeerPublicKeyMap(HashMap<String, [u8; PUBLIC_KEY_BYTES]>);

impl Error for BWTError {
    fn source(self: &BWTError) -> Option<&(dyn Error + 'static)> {
        match self {
            // The cause is the underlying implementation error type. Is implicitly
            // cast to the trait object `&error::Error`. This works because the
            // underlying type already implements the `Error` trait.
            BWTError::Other(err) => Some(&**err),
            _ => None,
        }
    }
}

impl fmt::Display for BWTError {
    fn fmt(self: &BWTError, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BWTError::InvalidMagicBytes => write!(f, "invalid magic bytes"),
            BWTError::InvalidHeaderBytes(n) => write!(f, "invalid number of header bytes {}", n),
            BWTError::UnsupportedVersion(version) => write!(f, "unsupported version {}", version),
            BWTError::Other(err) => err.fmt(f),
        }
    }
}

impl From<TryFromPrimitiveError<Typ>> for BWTError {
    fn from(err: TryFromPrimitiveError<Typ>) -> BWTError {
        BWTError::Other(Box::new(err))
    }
}

impl From<TryFromSliceError> for BWTError {
    fn from(err: TryFromSliceError) -> BWTError {
        BWTError::Other(Box::new(err))
    }
}

impl TryFrom<&[u8]> for InternalHeader {
    type Error = BWTError;
    fn try_from(buf: &[u8]) -> Result<InternalHeader, BWTError> {
        if buf.len() < HEADER_BYTES {
            Err(BWTError::InvalidHeaderBytes(buf.len()))
        } else {
            Ok(InternalHeader {
                typ: try_derive_typ(buf)?,
                iat: u64::from_be_bytes(buf[4..12].try_into()?),
                exp: u64::from_be_bytes(buf[12..20].try_into()?),
                kid: buf[20..36].try_into()?,
                nonce: buf[36..48].try_into()?,
                base64_kid: base64_encode(&buf[20..36]),
            })
        }
    }
}

impl TryFrom<(&Header, &[u8])> for InternalHeader {
    type Error = BWTError;
    fn try_from((header, nonce): (&Header, &[u8])) -> Result<InternalHeader, BWTError> {
        Ok(InternalHeader {
            typ: header.typ,
            iat: header.iat,
            exp: header.exp,
            kid: header.kid,
            nonce: nonce.try_into()?,
            base64_kid: base64_encode(&header.kid),
        })
    }
}

impl Into<Header> for InternalHeader {
    fn into(self: InternalHeader) -> Header {
        Header {
            typ: self.typ,
            iat: self.iat,
            exp: self.exp,
            kid: self.kid,
        }
    }
}

impl Into<[u8; HEADER_BYTES]> for InternalHeader {
    fn into(self: InternalHeader) -> [u8; HEADER_BYTES] {
        let mut buf: [u8; HEADER_BYTES] = [0u8; HEADER_BYTES];

        buf[0..3].copy_from_slice(&MAGIC_BWT);
        buf[3] = self.typ.into();
        buf[4..12].copy_from_slice(&self.iat.to_be_bytes());
        buf[12..20].copy_from_slice(&self.exp.to_be_bytes());
        buf[20..36].copy_from_slice(&self.kid);
        buf[36..48].copy_from_slice(&self.nonce);

        buf
    }
}

impl From<&[PeerPublicKey]> for PeerPublicKeyMap {
    fn from(peer_public_keys: &[PeerPublicKey]) -> PeerPublicKeyMap {
        let mut map: HashMap<String, [u8; PUBLIC_KEY_BYTES]> = HashMap::new();

        for peer_public_key in peer_public_keys.iter() {
            map.insert(
                base64_encode(&peer_public_key.kid[..]),
                peer_public_key.public_key,
            );
        }

        PeerPublicKeyMap(map)
    }
}

impl Header {
    fn is_valid(self: &Header) -> bool {
        let typ: u8 = self.typ.into();

        let now: u64 = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_millis() as u64,
            _ => return false,
        };

        typ >= MIN_SUPPORTED_VERSION
            && typ <= MAX_SUPPORTED_VERSION
            && self.iat <= now
            && self.exp > now
    }
}

impl InternalHeader {
    fn is_valid(self: &InternalHeader) -> bool {
        let typ: u8 = self.typ.into();

        let now: u64 = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_millis() as u64,
            _ => return false,
        };

        self.base64_kid.len() == BASE64_KID_CHARS
            && typ >= MIN_SUPPORTED_VERSION
            && typ <= MAX_SUPPORTED_VERSION
            && self.iat <= now
            && self.exp > now
    }
}

fn try_derive_typ(buf: &[u8]) -> Result<Typ, BWTError> {
    let version: u8 = buf[3];

    let mut diff: u8 = 0;

    for i in 0..3 {
        diff |= buf[i] ^ MAGIC_BWT[i];
    }

    if diff != 0 {
        Err(BWTError::InvalidMagicBytes)
    } else if version < MIN_SUPPORTED_VERSION || version > MAX_SUPPORTED_VERSION {
        Err(BWTError::UnsupportedVersion(version))
    } else {
        Ok(Typ::try_from(version)?)
    }
}

fn concat_token(aad: &[u8], ciphertext: &[u8], tag: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        base64_encode(aad),
        base64_encode(ciphertext),
        base64_encode(tag)
    )
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
