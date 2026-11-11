//! `der`: Minimal, zero-allocation ASN.1 DER / BER encoding and decoding primitives
//! for SPNEGO (RFC 4178), Kerberos v5 (RFC 4120), and LDAP (RFC 4511).

use crate::CoreError;

pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else {
        vec![
            0x83,
            (len >> 16) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

pub fn decode_tlv(data: &[u8]) -> Result<(u8, &[u8], &[u8]), CoreError> {
    if data.len() < 2 {
        return Err(CoreError::BufferUnderflow {
            needed: 2,
            available: data.len(),
        });
    }
    let tag = data[0];
    let first_len = data[1];
    let (len, hdr_len) = if (first_len & 0x80) == 0 {
        (first_len as usize, 2usize)
    } else {
        let num_bytes = (first_len & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || data.len() < 2 + num_bytes {
            return Err(CoreError::ProtocolError("Invalid ASN.1 DER length".into()));
        }
        let mut l = 0usize;
        for i in 0..num_bytes {
            l = (l << 8) | (data[2 + i] as usize);
        }
        (l, 2 + num_bytes)
    };

    if data.len() < hdr_len + len {
        return Err(CoreError::BufferUnderflow {
            needed: hdr_len + len,
            available: data.len(),
        });
    }
    Ok((tag, &data[hdr_len..hdr_len + len], &data[hdr_len + len..]))
}

pub fn decode_integer(bytes: &[u8]) -> Result<i64, CoreError> {
    let (tag, val, _) = decode_tlv(bytes)?;
    if tag != 0x02 || val.is_empty() || val.len() > 8 {
        return Err(CoreError::ProtocolError("Expected ASN.1 INTEGER".into()));
    }
    let mut out = if (val[0] & 0x80) != 0 { -1i64 } else { 0i64 };
    for &b in val {
        out = (out << 8) | (b as i64);
    }
    Ok(out)
}

pub fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let len_bytes = encode_length(value.len());
    let mut out = Vec::with_capacity(1 + len_bytes.len() + value.len());
    out.push(tag);
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(value);
    out
}

pub fn encode_sequence(elements: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = elements.iter().map(|e| e.len()).sum();
    let mut body = Vec::with_capacity(total);
    for el in elements {
        body.extend_from_slice(el);
    }
    encode_tlv(0x30, &body)
}

pub fn encode_context_explicit(tag_num: u8, inner: &[u8]) -> Vec<u8> {
    encode_tlv(0xA0 | (tag_num & 0x1F), inner)
}

pub fn encode_application(app_num: u8, inner: &[u8]) -> Vec<u8> {
    if app_num < 31 {
        encode_tlv(0x60 | app_num, inner)
    } else {
        let len_bytes = encode_length(inner.len());
        let mut out = Vec::with_capacity(2 + len_bytes.len() + inner.len());
        out.push(0x7F);
        out.push(app_num);
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(inner);
        out
    }
}

pub fn encode_integer(val: i64) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        if (bytes[start] == 0x00 && (bytes[start + 1] & 0x80) == 0)
            || (bytes[start] == 0xFF && (bytes[start + 1] & 0x80) != 0)
        {
            start += 1;
        } else {
            break;
        }
    }
    encode_tlv(0x02, &bytes[start..])
}

pub fn encode_general_string(s: &str) -> Vec<u8> {
    encode_tlv(0x1B, s.as_bytes())
}

pub fn encode_generalized_time(s: &str) -> Vec<u8> {
    encode_tlv(0x18, s.as_bytes())
}

pub fn encode_bit_string_u32(flags: u32) -> Vec<u8> {
    let mut body = vec![0x00];
    body.extend_from_slice(&flags.to_be_bytes());
    encode_tlv(0x03, &body)
}

pub fn encode_octet_string(bytes: &[u8]) -> Vec<u8> {
    encode_tlv(0x04, bytes)
}

pub fn encode_oid(raw_oid_bytes: &[u8]) -> Vec<u8> {
    encode_tlv(0x06, raw_oid_bytes)
}

pub fn decode_oid(data: &[u8]) -> Result<(&[u8], &[u8]), CoreError> {
    let (tag, val, rest) = decode_tlv(data)?;
    if tag != 0x06 {
        return Err(CoreError::ProtocolError(format!(
            "Expected ASN.1 OID (0x06), got 0x{:02X}",
            tag
        )));
    }
    Ok((val, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_tlv_and_sequence_roundtrip() {
        let seq = encode_sequence(&[
            encode_integer(42),
            encode_octet_string(b"antislop"),
            encode_oid(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]),
        ]);
        let (tag, val, rest) = decode_tlv(&seq).unwrap();
        assert_eq!(tag, 0x30);
        assert!(rest.is_empty());

        let (tag1, val1, rest1) = decode_tlv(val).unwrap();
        assert_eq!(tag1, 0x02);
        assert_eq!(decode_integer(&encode_tlv(tag1, val1)).unwrap(), 42);

        let (tag2, val2, rest2) = decode_tlv(rest1).unwrap();
        assert_eq!(tag2, 0x04);
        assert_eq!(val2, b"antislop");

        let (oid, rest3) = decode_oid(rest2).unwrap();
        assert_eq!(oid, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);
        assert!(rest3.is_empty());
    }
}
