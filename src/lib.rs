// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the APACHE 2.0 license found in
// the LICENSE file in the root directory of this source tree.

use anyhow::{anyhow, Result};
use core::ops::Neg;

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, traits::IsIdentity};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::{Digest, Sha512};

use std::fs::File;
use std::io::prelude::*;

#[macro_use]
extern crate log;

extern crate string_builder;

use crate::test_vectors::generate_test_vectors;

pub mod algorithm2;
mod non_reducing_scalar52;
pub mod test_vectors;

// The 8-torsion subgroup E[8].
//
// In the case of Curve25519, it is cyclic; the i-th element of
// the array is [i]P, where P is a point of order 8
// generating E[8].
//
// Thus E[4] is the points indexed by `0,2,4,6`, and
// E[2] is the points indexed by `0,4`.
//
// The following byte arrays have been ported from curve25519-dalek /backend/serial/u64/constants.rs
// and they represent the serialised version of the CompressedEdwardsY points.
pub const EIGHT_TORSION: [[u8; 32]; 8] = [
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ], // (0,1), order 1, neutral element
    [
        199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250, 44,
        57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 122,
    ], // order 8
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128,
    ], // order 4
    [
        38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223, 172,
        5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 5,
    ], // order 8
    [
        236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ], // order 2
    [
        38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223, 172,
        5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 133,
    ], // order 8
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ], // order 4
    [
        199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250, 44,
        57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 250,
    ], // order 8
];

// Non canonical representations of those torsion points
// for which the non-canonical serialization exist
// First 3 elements are neutral elements
const EIGHT_TORSION_NON_CANONICAL: [[u8; 32]; 6] = [
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128,
    ], // neutral element, incorrect x-sign : (-0, 1) order 1
    [
        238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ], // neutral element, incorrect x-sign : (-0, 2^255 - 18) order 1
    [
        236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ], // incorrect x-sign : (-0, -1) order 2
    [
        238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ], // neutral element with large y component : (0, 2^255 - 18) order 1
    [
        237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ], // (-sqrt(-1), 2^255 - 19) order 4
    [
        237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ], // (sqrt(-1), 2^255 - 19) order 4
];

// 8 as a Scalar - to reflect instructions of "interpreting values as
// integers"
fn eight() -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[31] |= 8;
    Scalar::from_bytes_mod_order(bytes)
}

fn multiple_of_eight_le(scalar: Scalar) -> bool {
    scalar.to_bytes()[31].trailing_zeros() >= 3
}

pub fn check_slice_size<'a>(
    slice: &'a [u8],
    expected_len: usize,
    arg_name: &'static str,
) -> Result<&'a [u8]> {
    if slice.len() != expected_len {
        return Err(anyhow!(
            "slice length for {} must be {} characters, got {}",
            arg_name,
            expected_len,
            slice.len()
        ));
    }
    Ok(slice)
}

pub fn deserialize_point(pt: &[u8]) -> Result<EdwardsPoint> {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(check_slice_size(pt, 32, "pt")?);

    curve25519_dalek::edwards::CompressedEdwardsY(bytes)
        .decompress()
        .ok_or_else(|| anyhow!("Point decompression failed!"))
}

#[allow(dead_code)]
fn deserialize_scalar(scalar: &[u8]) -> Result<Scalar> {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(check_slice_size(scalar, 32, "scalar")?);

    // This permissive pass-through can produce large scalars!
    Ok(curve25519_dalek::scalar::Scalar::from_bits(bytes))
}

#[allow(dead_code)]
fn deserialize_signature(sig_bytes: &[u8]) -> Result<(EdwardsPoint, Scalar)> {
    let checked_sig_bytes = check_slice_size(sig_bytes, 64, "sig_bytes")?;
    let r = deserialize_point(&checked_sig_bytes[..32])?;
    let s = deserialize_scalar(&checked_sig_bytes[32..])?;
    Ok((r, s))
}

pub fn serialize_signature(r: &EdwardsPoint, s: &Scalar) -> Vec<u8> {
    [&r.compress().as_bytes()[..], &s.as_bytes()[..]].concat()
}

pub fn compute_hram(message: &[u8], pub_key: &EdwardsPoint, signature_r: &EdwardsPoint) -> Scalar {
    let k_bytes = Sha512::default()
        .chain(&signature_r.compress().as_bytes())
        .chain(&pub_key.compress().as_bytes()[..])
        .chain(&message);
    // curve25519_dalek is stuck on an old digest version, so we can't do
    // Scalar::from_hash
    let mut k_output = [0u8; 64];
    k_output.copy_from_slice(k_bytes.finalize().as_slice());
    Scalar::from_bytes_mod_order_wide(&k_output)
}

fn compute_hram_with_r_array(message: &[u8], pub_key: &EdwardsPoint, signature_r: &[u8]) -> Scalar {
    let k_bytes = Sha512::default()
        .chain(&signature_r)
        .chain(&pub_key.compress().as_bytes()[..])
        .chain(&message);
    // curve25519_dalek is stuck on an old digest version, so we can't do
    // Scalar::from_hash
    let mut k_output = [0u8; 64];
    k_output.copy_from_slice(k_bytes.finalize().as_slice());
    Scalar::from_bytes_mod_order_wide(&k_output)
}

fn compute_hram_with_pk_array(
    message: &[u8],
    pub_key_arr: &[u8],
    signature_r: &EdwardsPoint,
) -> Scalar {
    let k_bytes = Sha512::default()
        .chain(&signature_r.compress().as_bytes())
        .chain(&pub_key_arr)
        .chain(&message);
    // curve25519_dalek is stuck on an old digest version, so we can't do
    // Scalar::from_hash
    let mut k_output = [0u8; 64];
    k_output.copy_from_slice(k_bytes.finalize().as_slice());
    Scalar::from_bytes_mod_order_wide(&k_output)
}

pub fn verify_cofactored(
    message: &[u8],
    pub_key: &EdwardsPoint,
    unpacked_signature: &(EdwardsPoint, Scalar),
) -> Result<()> {
    let k = compute_hram(message, pub_key, &unpacked_signature.0);
    verify_final_cofactored(pub_key, unpacked_signature, &k)
}

pub fn verify_cofactorless(
    message: &[u8],
    pub_key: &EdwardsPoint,
    unpacked_signature: &(EdwardsPoint, Scalar),
) -> Result<()> {
    let k = compute_hram(message, pub_key, &unpacked_signature.0);
    verify_final_cofactorless(pub_key, unpacked_signature, &k)
}

fn verify_pre_reduced_cofactored(
    message: &[u8],
    pub_key: &EdwardsPoint,
    unpacked_signature: &(EdwardsPoint, Scalar),
) -> Result<()> {
    let k = compute_hram(message, pub_key, &unpacked_signature.0);
    verify_final_pre_reduced_cofactored(pub_key, unpacked_signature, &k)
}

fn verify_final_cofactored(
    pub_key: &EdwardsPoint,
    unpacked_signature: &(EdwardsPoint, Scalar),
    hash: &Scalar,
) -> Result<()> {
    let rprime = EdwardsPoint::vartime_double_scalar_mul_basepoint(
        hash,
        &pub_key.neg(),
        &unpacked_signature.1,
    );
    if (unpacked_signature.0 - rprime)
        .mul_by_cofactor()
        .is_identity()
    {
        Ok(())
    } else {
        Err(anyhow!("Invalid cofactored signature"))
    }
}

fn verify_final_pre_reduced_cofactored(
    pub_key: &EdwardsPoint,
    unpacked_signature: &(EdwardsPoint, Scalar),
    hash: &Scalar,
) -> Result<()> {
    let eight_hash = eight() * hash;
    let eight_s = eight() * unpacked_signature.1;

    let rprime =
        EdwardsPoint::vartime_double_scalar_mul_basepoint(&eight_hash, &pub_key.neg(), &eight_s);
    if (unpacked_signature.0.mul_by_cofactor() - rprime).is_identity() {
        Ok(())
    } else {
        Err(anyhow!("Invalid pre-reduced cofactored signature"))
    }
}

fn verify_final_cofactorless(
    pub_key: &EdwardsPoint,
    unpacked_signature: &(EdwardsPoint, Scalar),
    hash: &Scalar,
) -> Result<()> {
    let rprime = EdwardsPoint::vartime_double_scalar_mul_basepoint(
        hash,
        &pub_key.neg(),
        &unpacked_signature.1,
    );
    if (unpacked_signature.0 - rprime).is_identity() {
        Ok(())
    } else {
        Err(anyhow!("Invalid cofactorless signature"))
    }
}

pub fn new_rng() -> impl RngCore {
    let mut pi_bytes = [0u8; 32];
    for i in 0..4 {
        pi_bytes[8 * i..8 * i + 8].copy_from_slice(&std::f64::consts::PI.to_le_bytes()[..]);
    }
    StdRng::from_seed(pi_bytes)
}

fn pick_small_nonzero_point(idx: usize) -> EdwardsPoint {
    deserialize_point(&EIGHT_TORSION[(idx % 7 + 1)]).unwrap()
}

pub fn main() -> Result<()> {
    env_logger::init();
    let vec = generate_test_vectors();

    // Write test vectors to json
    let cases_json = serde_json::to_string(&vec)?;
    let mut file = File::create("cases.json")?;
    file.write_all(cases_json.as_bytes())?;

    // Write test vectors to txt (to ease testing C implementations)
    let mut file = File::create("cases.txt")?;
    file.write_all(vec.len().to_string().as_bytes())?;
    for tv in vec.iter() {
        file.write_all(b"\nmsg=")?;
        file.write_all(hex::encode(&tv.message).as_bytes())?;
        file.write_all(b"\npbk=")?;
        file.write_all(hex::encode(&tv.pub_key).as_bytes())?;
        file.write_all(b"\nsig=")?;
        file.write_all(hex::encode(&tv.signature).as_bytes())?;
    }
    Ok(())
}
