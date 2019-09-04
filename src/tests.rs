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
