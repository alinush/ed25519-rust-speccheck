use crate::{check_slice_size, verify_cofactored};
use anyhow::{anyhow, Result};
/// This file implements the individual signature verification algorithm from [CGN20e], a.k.a.
/// Algorithm 2.
///
/// References:
/// [CGN20e] Taming the many EdDSAs; by Konstantinos Chalkias and François Garillot and Valeria Nikolaenko; in Cryptology ePrint Archive, Report 2020/1244; 2020; https://ia.cr/2020/1244
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

pub fn is_canonical_point_encoding(bytes: &[u8]) -> bool {
    bytes.len() == 32 && is_canonical_y(bytes) && !is_small_order_special_case(bytes)
}

fn is_canonical_y(bytes: &[u8]) -> bool {
    if bytes[0] < 237 {
        true
    } else {
        for i in 1..=30 {
            if bytes[i] != 255 {
                return true
            }
        }

        (bytes[31] | 128) != 255
    }
}

fn is_small_order_special_case(bytes: &[u8]) -> bool {
    is_small_order_case_9(bytes) || is_small_order_case_10(bytes)
}

/// Returns true if this is point #9 (0x01 00...0080) from Table 1 and Table 2 in [CGN20e]
fn is_small_order_case_9(bytes: &[u8]) -> bool {
    if bytes[0] != 0x01 {
        false
    } else {
        for i in 1..=30 {
            if bytes[i] != 0x00 {
                return false
            }
        }

        bytes[31] == 0x80
    }
}

/// Returns true if this is point #10 (0xEC FF...FFFF) from Table 1 and Table 2 in [CGN20e]
fn is_small_order_case_10(bytes: &[u8]) -> bool {
    if bytes[0] != 0xEC {
        false
    } else {
        for i in 1..=31 {
            if bytes[i] != 0xFF {
                return false
            }
        }

        true
    }
}

pub fn deserialize_point(pt: &[u8]) -> Result<EdwardsPoint> {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(check_slice_size(pt, 32, "pt")?);

    // Check canonical encoding
    if !is_canonical_point_encoding(&bytes[..]) {
        return Err(anyhow!("Non-canonical point encoding!"));
    }

    curve25519_dalek::edwards::CompressedEdwardsY(bytes)
        .decompress()
        .ok_or_else(|| anyhow!("Point decompression failed!"))
}

#[allow(non_snake_case)]
pub fn deserialize_R(pt: &[u8]) -> Result<EdwardsPoint> {
    deserialize_point(pt)
}

pub fn deserialize_pk(pt: &[u8]) -> Result<EdwardsPoint> {
    deserialize_point(pt)
}

pub fn deserialize_s(scalar: &[u8]) -> Result<Scalar> {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(check_slice_size(scalar, 32, "scalar")?);

    // Enforces s < \ell
    match curve25519_dalek::scalar::Scalar::from_canonical_bytes(bytes) {
        None => return Err(anyhow!("non-canonical s")),
        Some(s) => Ok(s),
    }
}

#[allow(non_snake_case)]
pub fn deserialize_signature(sig_bytes: &[u8]) -> Result<(Scalar, EdwardsPoint)> {
    let checked_sig_bytes = check_slice_size(sig_bytes, 64, "sig_bytes")?;

    let s = deserialize_s(&checked_sig_bytes[32..])?;
    let R = deserialize_R(&checked_sig_bytes[..32])?;

    Ok((s, R))
}

#[allow(non_snake_case)]
pub fn verify_signature(s: &Scalar, R: &EdwardsPoint, msg_bytes: &[u8], pk: &EdwardsPoint) -> bool {
    // Check public key is not of small order
    if pk.is_small_order() {
        return false;
    }

    // Co-factored verification
    verify_cofactored(msg_bytes, pk, &(*R, *s)).is_ok()
}
