use super::*;

#[test]
fn test_header_marshalling() -> Result<(), Box<Error>> {
    let internal_header: InternalHeader = InternalHeader {
        typ: Typ::BWTv0,
        iat: 1,
        exp: 2,
        kid: [0u8; 16],
        nonce: [0u8; 12],
        base64_kid: "AAAAAAAAAAAAAAAAAAAAAA==".to_string(),
    };

    let header: Header = Header {
        typ: Typ::BWTv0,
        iat: 1,
        exp: 2,
        kid: [0u8; 16],
    };

    let buf: [u8; HEADER_BYTES] = internal_header.clone().into();

    let internal_header_a: InternalHeader = InternalHeader::try_from(&buf[..])?;

    let internal_header_b: InternalHeader =
        InternalHeader::try_from((&header, &internal_header.nonce[..]))?;

    let header_a: Header = internal_header.clone().into();

    assert_eq!(internal_header_a.nonce, internal_header.nonce);
    assert_eq!(internal_header_a.typ, internal_header.typ);
    assert_eq!(internal_header_a.iat, internal_header.iat);
    assert_eq!(internal_header_a.exp, internal_header.exp);
    assert_eq!(internal_header_a.kid, internal_header.kid);

    assert_eq!(internal_header_b.nonce, internal_header.nonce);
    assert_eq!(internal_header_b.typ, internal_header.typ);
    assert_eq!(internal_header_b.iat, internal_header.iat);
    assert_eq!(internal_header_b.exp, internal_header.exp);
    assert_eq!(internal_header_b.kid, internal_header.kid);

    assert_eq!(header_a.typ, header.typ);
    assert_eq!(header_a.iat, header.iat);
    assert_eq!(header_a.exp, header.exp);
    assert_eq!(header_a.kid, header.kid);

    Ok(())
}

#[test]
fn test_peer_public_key_map() -> Result<(), Box<Error>> {
    let peer_public_keys: Vec<PeerPublicKey> = vec![
        PeerPublicKey {
            public_key: [0u8; PUBLIC_KEY_BYTES],
            kid: [77, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        },
        PeerPublicKey {
            public_key: [0u8; PUBLIC_KEY_BYTES],
            kid: [99, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        },
    ];

    let PeerPublicKeyMap(public_key_map): PeerPublicKeyMap =
        PeerPublicKeyMap::from(&peer_public_keys[..]);

    assert_eq!(public_key_map.len(), 2usize);
    assert_eq!(public_key_map.get("QldU"), None);

    let base64_kid_0: String = base64_encode(&peer_public_keys[0].kid);
    let public_key_0: &[u8; PUBLIC_KEY_BYTES] = public_key_map.get(&base64_kid_0).unwrap();

    let base64_kid_1: String = base64_encode(&peer_public_keys[1].kid);
    let public_key_1: &[u8; PUBLIC_KEY_BYTES] = public_key_map.get(&base64_kid_1).unwrap();

    assert_eq!(*public_key_0, [0u8; PUBLIC_KEY_BYTES]);
    assert_eq!(*public_key_1, [0u8; PUBLIC_KEY_BYTES]);

    Ok(())
}

#[test]
fn test_concat_token() -> Result<(), Box<Error>> {
    let aad: Vec<u8> = vec![66];
    let ciphertext: Vec<u8> = vec![87];
    let tag: Vec<u8> = vec![84];

    let token: String = concat_token(&aad, &ciphertext, &tag);

    assert_eq!(&token, "Qg==.Vw==.VA==");

    Ok(())
}

#[test]
fn test_is_valid_header() -> Result<(), Box<Error>> {
    let invalid_header: Header = Header {
        typ: Typ::BWTv0,
        iat: 0,
        exp: 1,
        kid: [0u8; KID_BYTES],
    };

    let valid_header: Header = Header {
        typ: Typ::BWTv0,
        iat: 0,
        exp: 9999999999999,
        kid: [0u8; KID_BYTES],
    };

    assert!(!invalid_header.is_valid());
    assert!(valid_header.is_valid());

    Ok(())
}

#[test]
fn test_is_valid_internal_header() -> Result<(), Box<Error>> {
    let invalid_internal_header: InternalHeader = InternalHeader {
        typ: Typ::BWTv0,
        iat: 0,
        exp: 1,
        kid: [0u8; KID_BYTES],
        nonce: [0u8; NONCE_BYTES],
        base64_kid: "deadbeefdeadbeefdeadbeef".to_string(),
    };

    let valid_internal_header: InternalHeader = InternalHeader {
        typ: Typ::BWTv0,
        iat: 0,
        exp: 9999999999999,
        kid: [0u8; KID_BYTES],
        nonce: [0u8; NONCE_BYTES],
        base64_kid: "deadbeefdeadbeefdeadbeef".to_string(),
    };

    assert!(!invalid_internal_header.is_valid());
    assert!(valid_internal_header.is_valid());

    Ok(())
}
