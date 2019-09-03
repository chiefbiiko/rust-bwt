use super::*;

#[test]
fn test_header_marshalling() -> () {
    let internal_header: InternalHeader = InternalHeader {
        header: &Header {
            typ: "BWTv0",
            iat: 1,
            exp: 2,
            kid: &vec![0u8; 16],
        },
        nonce: &vec![0u8; 12],
    };

    let _internal_header: InternalHeader =
        buffer_to_internal_header(&internal_header_to_buffer(&internal_header));

    assert_eq!(_internal_header, internal_header);
}
