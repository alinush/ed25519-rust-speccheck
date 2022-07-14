use crate::non_reducing_scalar52::Scalar52;
use crate::{
    compute_hram, compute_hram_with_pk_array, compute_hram_with_r_array, deserialize_point,
    deserialize_scalar, eight, multiple_of_eight_le, new_rng, non_reducing_scalar52,
    pick_small_nonzero_point, serialize_signature, verify_cofactored, verify_cofactorless,
    verify_pre_reduced_cofactored, EIGHT_TORSION_NON_CANONICAL,
};
use anyhow::{anyhow, Result};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use rand::RngCore;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha512};
use std::ops::Neg;
use string_builder::Builder;

///////////
// Cases //
///////////

pub struct TestVector {
    #[allow(dead_code)]
    pub message: [u8; 32],
    #[allow(dead_code)]
    pub pub_key: [u8; 32],
    #[allow(dead_code)]
    pub signature: Vec<u8>,
}

impl Serialize for TestVector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Color", 3)?;
        state.serialize_field("message", &hex::encode(&self.message))?;
        state.serialize_field("pub_key", &hex::encode(&self.pub_key))?;
        state.serialize_field("signature", &hex::encode(&self.signature))?;
        state.end()
    }
}

//////////////////////
// 0 (cofactored)   //
// 1 (cofactorless) //
//////////////////////

pub fn zero_small_small() -> Result<(TestVector, TestVector), anyhow::Error> {
    let mut rng = new_rng();
    // Pick a torsion point
    let small_idx: usize = rng.next_u64() as usize;

    let pub_key = pick_small_nonzero_point(small_idx + 1);
    let r = pub_key.neg();
    let s = Scalar::zero();

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    if (r + compute_hram(&message, &pub_key, &r) * pub_key).is_identity() {
        return Err(anyhow!("wrong rng seed"));
    }
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    debug!(
        "S=0, small A, small R\n\
             passes cofactored, fails cofactorless, repudiable\n\
             \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv1 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    while !(r + compute_hram(&message, &pub_key, &r) * pub_key).is_identity() {
        rng.fill_bytes(&mut message);
    }

    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());

    debug!(
        "S=0, small A, small R\n\
         passes cofactored, passes cofactorless, repudiable\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv2 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    Ok((tv1, tv2))
}

//////////////////////
// 2 (cofactored)   //
// 3 (cofactorless) //
//////////////////////

pub fn non_zero_mixed_small() -> Result<(TestVector, TestVector)> {
    let mut rng = new_rng();
    // Pick a random Scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let s = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(s.is_canonical());
    debug_assert!(s != Scalar::zero());

    let r0 = s * ED25519_BASEPOINT_POINT;

    // Pick a torsion point
    let small_idx: usize = rng.next_u64() as usize;
    let pub_key = pick_small_nonzero_point(small_idx + 1);

    let r = r0 + pub_key.neg();

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    if (pub_key.neg() + compute_hram(&message, &pub_key, &r) * pub_key).is_identity() {
        return Err(anyhow!("wrong rng seed"));
    }
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    debug!(
        "S > 0, small A, mixed R\n\
             passes cofactored, fails cofactorless, repudiable\n\
             \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv1 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    while !(pub_key.neg() + compute_hram(&message, &pub_key, &r) * pub_key).is_identity() {
        rng.fill_bytes(&mut message);
    }
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());
    debug!(
        "S > 0, small A, mixed R\n\
         passes cofactored, passes cofactorless, repudiable\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv2 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    Ok((tv1, tv2))
}

//////////////////////
// 4 (cofactored)   //
// 5 (cofactorless) //
//////////////////////

// The symmetric case from non_zero_mixed_small
pub fn non_zero_small_mixed() -> Result<(TestVector, TestVector)> {
    let mut rng = new_rng();
    // Pick a random scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let a = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(a.is_canonical());
    debug_assert!(a != Scalar::zero());

    let pub_key_component = a * ED25519_BASEPOINT_POINT;

    // Pick a torsion point
    let small_idx: usize = rng.next_u64() as usize;
    let r = pick_small_nonzero_point(small_idx + 1);

    let pub_key = pub_key_component + r.neg();

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    if (r + compute_hram(&message, &pub_key, &r) * r.neg()).is_identity() {
        return Err(anyhow!("wrong rng seed"));
    }
    let s = compute_hram(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    debug!(
        "S > 0, mixed A, small R\n\
             passes cofactored, fails cofactorless, leaks private key\n\
             \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );

    let tv1 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    while !(r + compute_hram(&message, &pub_key, &r) * r.neg()).is_identity() {
        rng.fill_bytes(&mut message);
    }
    let s = compute_hram(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());
    debug!(
        "S > 0, mixed A, small R\n\
         passes cofactored, passes cofactorless, leaks private key\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv2 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    Ok((tv1, tv2))
}

//////////////////////
// 6 (cofactored)   //
// 7 (cofactorless) //
//////////////////////

pub fn non_zero_mixed_mixed() -> Result<(TestVector, TestVector)> {
    let mut rng = new_rng();
    // Pick a random scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let a = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(a.is_canonical());
    debug_assert!(a != Scalar::zero());
    // Pick a random nonce
    let nonce_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);

    // Pick a torsion point
    let small_idx: usize = rng.next_u64() as usize;
    let small_pt = pick_small_nonzero_point(small_idx + 1);

    // generate the r of a "normal" signature
    let prelim_pub_key = a * ED25519_BASEPOINT_POINT;

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    let mut h = Sha512::new();
    h.update(&nonce_bytes);
    h.update(&message);

    let mut output = [0u8; 64];
    output.copy_from_slice(h.finalize().as_slice());
    let mut prelim_r = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&output);

    let pub_key = prelim_pub_key + small_pt;
    let mut r = prelim_r * ED25519_BASEPOINT_POINT + small_pt.neg();

    if (small_pt.neg() + compute_hram(&message, &pub_key, &r) * small_pt).is_identity() {
        return Err(anyhow!("wrong rng seed"));
    }
    let s = prelim_r + compute_hram(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    debug!(
        "S > 0, mixed A, mixed R\n\
             passes cofactored, fails cofactorless\n\
             \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );

    let tv1 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    while !(small_pt.neg() + compute_hram(&message, &pub_key, &r) * small_pt).is_identity() {
        rng.fill_bytes(&mut message);
        let mut h = Sha512::new();
        h.update(&nonce_bytes);
        h.update(&message);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        prelim_r = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&output);

        r = prelim_r * ED25519_BASEPOINT_POINT + small_pt.neg();
    }
    let s = prelim_r + compute_hram(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());
    debug!(
        "S > 0, mixed A, mixed R\n\
         passes cofactored, passes cofactorless\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv2 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    Ok((tv1, tv2))
}

////////////////////////////
// 8 (pre-reduced scalar) //
////////////////////////////

fn pre_reduced_scalar() -> TestVector {
    let mut rng = new_rng();

    // Pick a random scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let a = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(a.is_canonical());
    debug_assert!(a != Scalar::zero());
    // Pick a random nonce
    let nonce_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);

    // generate the r of a "normal" signature
    let prelim_pub_key = a * ED25519_BASEPOINT_POINT;

    // Pick a torsion point
    let small_idx: usize = rng.next_u64() as usize;
    let small_pt = pick_small_nonzero_point(small_idx + 1);
    let pub_key = prelim_pub_key + small_pt;

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    let mut h = Sha512::new();
    h.update(&nonce_bytes);
    h.update(&message);

    let mut output = [0u8; 64];
    output.copy_from_slice(h.finalize().as_slice());
    let r_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&output);
    let r = r_scalar * ED25519_BASEPOINT_POINT;

    // grind a k so that 8*k gets reduced to a number NOT multiple of eight,
    // and add a small order component to the public key.
    while multiple_of_eight_le(eight() * compute_hram(&message, &pub_key, &r)) {
        rng.fill_bytes(&mut message);
    }

    let s = r_scalar + compute_hram(&message, &pub_key, &r) * a;

    // that's because we do cofactored verification without pre-reducing scalars
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());

    // pre-reducing is a mistake
    debug_assert!(verify_pre_reduced_cofactored(&message, &pub_key, &(r, s)).is_err());

    // as expected
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    debug!(
        "S > 0, mixed A, large order R\n\
         passes cofactored, fails pre-reducing cofactored, fails cofactorless\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    }
}

////////
// 9  //
////////

fn large_s() -> Result<TestVector> {
    let mut rng = new_rng();
    // Pick a random scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let a = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(a.is_canonical());
    debug_assert!(a != Scalar::zero());
    // Pick a random nonce
    let nonce_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);

    // generate the r of a "normal" signature
    let pub_key = a * ED25519_BASEPOINT_POINT;

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    let mut h = Sha512::new();
    h.update(&nonce_bytes);
    h.update(&message);

    let mut output = [0u8; 64];
    output.copy_from_slice(h.finalize().as_slice());
    let r_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&output);

    let r = r_scalar * ED25519_BASEPOINT_POINT;

    let s = r_scalar + compute_hram(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());

    let s_nonreducing = Scalar52::from_bytes(&s.to_bytes());
    let s_prime_bytes = Scalar52::add(&s_nonreducing, &non_reducing_scalar52::L).to_bytes();
    // using deserialize_scalar is key here, we use `from_bits` to represent
    // the scalar
    let s_prime = deserialize_scalar(&s_prime_bytes)?;

    debug_assert!(s != s_prime);
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s_prime)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s_prime)).is_ok());

    debug!(
        "S > L, large order A, large order R\n\
         passes cofactored, passes  cofactorless, often excluded from both, breaks strong unforgeability\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s_prime))
    );
    let tv = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s_prime),
    };

    Ok(tv)
}

////////
// 10 //
////////

fn really_large_s() -> Result<TestVector> {
    let mut rng = new_rng();
    // Pick a random scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let a = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(a.is_canonical());
    debug_assert!(a != Scalar::zero());
    // Pick a random nonce
    let mut nonce_bytes = [0u8; 32];
    rng.fill_bytes(&mut nonce_bytes);

    // generate the r of a "normal" signature
    let pub_key = a * ED25519_BASEPOINT_POINT;

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    let mut h = Sha512::new();
    h.update(&nonce_bytes);
    h.update(&message);

    let mut output = [0u8; 64];
    output.copy_from_slice(h.finalize().as_slice());
    let r_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&output);

    let r = r_scalar * ED25519_BASEPOINT_POINT;

    let s = r_scalar + compute_hram(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());

    let mut s_nonreducing = Scalar52::from_bytes(&s.to_bytes());
    // perform the incomplete higher-bits check often used in place of s<L
    while (s_nonreducing.to_bytes()[31] as u8 & 224u8) == 0u8 {
        s_nonreducing = Scalar52::add(&s_nonreducing, &non_reducing_scalar52::L);
    }
    let s_prime_bytes = s_nonreducing.to_bytes();

    // using deserialize_scalar is key here, we use `from_bits` to represent
    // the scalar
    let s_prime = deserialize_scalar(&s_prime_bytes)?;

    debug_assert!(s != s_prime);
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s_prime)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s_prime)).is_ok());

    debug!(
        "S much larger than L, large order A, large order R\n\
         passes cofactored, passes  cofactorless, often excluded from both due to high bit checks, breaks strong unforgeability\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s_prime))
    );
    let tv = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s_prime),
    };

    Ok(tv)
}

///////////
// 11-12 //
///////////

// This test vector has R = (-0, 2^255 - 20) of order 2 in non-canonical form, serialialized as ECFFFF..FFFF.
// Libraries that reject non-canonical encodings of R or small-order R would reject both vectors.
// The first vector will pass cofactored and cofactorless verifications that reserialize R prior to hashing and fail those that do not reserialize R for the hash.
// The second vector will behave in an opposite way.
pub fn non_zero_small_non_canonical_mixed() -> Result<Vec<TestVector>> {
    let mut vec = Vec::new();

    // r not identity, with incorrect x sign and y coordinate larger than p
    let r_arr = EIGHT_TORSION_NON_CANONICAL[2];
    let mut rng = new_rng();
    // Pick a random scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let a = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(a.is_canonical());
    debug_assert!(a != Scalar::zero());

    let pub_key_component = a * ED25519_BASEPOINT_POINT;
    let r = deserialize_point(&r_arr[..32]).unwrap();

    let small_idx: usize = rng.next_u64() as usize;
    let r2 = pick_small_nonzero_point(small_idx + 1);
    let pub_key = pub_key_component + r2.neg();

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);

    while !(r + compute_hram(&message, &pub_key, &r) * r2.neg()).is_identity()
        || !(r + compute_hram_with_r_array(&message, &pub_key, &r_arr[..32]) * r2.neg())
            .is_identity()
    {
        rng.fill_bytes(&mut message);
    }
    let s = compute_hram(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());
    let mut signature = serialize_signature(&r, &s);
    signature[..32].clone_from_slice(&r_arr[..32]);
    debug!(
        "S > 0, mixed A, small non-canonical R\n\
         passes cofactored, passes cofactorless, leaks private key\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&signature)
    );
    let tv1 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature,
    };
    vec.push(tv1);

    let s = compute_hram_with_r_array(&message, &pub_key, &r_arr[..32]) * a;
    let mut signature = serialize_signature(&r, &s);
    signature[..32].clone_from_slice(&r_arr[..32]);
    debug!(
        "S > 0, mixed A, small non-canonical R\n\
         passes cofactored, passes cofactorless, leaks private key\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&signature)
    );
    let tv2 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature,
    };
    vec.push(tv2);

    Ok(vec)
}

///////////
// 13-14 //
///////////

// This test vector has A = (-0, 2^255 - 20) of order 2 in non-canonical form, serialialized as ECFFFF..FFFF.
// Libraries that reject non-canonical encodings of A or reject A of small order would reject both vectors.
// Libraries with cofactorless verification that accept the first vector,
// but reject the second reduce A prior to hashing.
// Libraries with cofactorless verification that reject the first vector,
// but accept the second do not reduce A prior to hashing.
// Both vectors pass for cofactored verification.
#[allow(dead_code)]
pub fn non_zero_mixed_small_non_canonical() -> Result<Vec<TestVector>> {
    let mut vec = Vec::new();

    // pk not identity, with only incorrect x sign
    let pub_key_arr = EIGHT_TORSION_NON_CANONICAL[2];

    let mut rng = new_rng();
    // Pick a random Scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let s = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(s.is_canonical());
    debug_assert!(s != Scalar::zero());

    let r0 = s * ED25519_BASEPOINT_POINT;
    let pub_key = deserialize_point(&pub_key_arr[..32]).unwrap();
    let r = r0 + pub_key.neg();

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);

    // succeeds when public key is reserialized
    while !(pub_key.neg() + compute_hram(&message, &pub_key, &r) * pub_key).is_identity()
        || (pub_key.neg() + compute_hram_with_pk_array(&message, &pub_key_arr[..32], &r) * pub_key)
            .is_identity()
    {
        rng.fill_bytes(&mut message);
    }
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());
    debug!(
        "S > 0, non-canonical A, mixed R\n\
         passes cofactored, passes cofactorless, repudiable\n\
         reserializes A\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv1 = TestVector {
        message,
        pub_key: pub_key_arr,
        signature: serialize_signature(&r, &s),
    };
    vec.push(tv1);

    // succeeds when public key is not-reserialized
    while !(pub_key.neg() + compute_hram_with_pk_array(&message, &pub_key_arr[..32], &r) * pub_key)
        .is_identity()
        || (pub_key.neg() + compute_hram(&message, &pub_key, &r) * pub_key).is_identity()
    {
        rng.fill_bytes(&mut message);
    }
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    debug!(
        "S > 0, non-canonical A, mixed R\n\
         passes cofactored, passes cofactorless, repudiable\n\
         does not reserialize A\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv2 = TestVector {
        message,
        pub_key: pub_key_arr,
        signature: serialize_signature(&r, &s),
    };
    vec.push(tv2);

    Ok(vec)
}

pub fn generate_test_vectors() -> Vec<TestVector> {
    let mut info = Builder::default();
    info.append("|  |    msg |    sig |  S   |    A  |    R  | cof-ed | cof-less |        comment        |\n");
    info.append("|---------------------------------------------------------------------------------------|\n");
    let mut vec = Vec::new();

    // #0: canonical S, small R, small A
    let (_tv1, tv2) = zero_small_small().unwrap();
    info.append(format!(
        "| 0| ..{:} | ..{:} |  = 0 | small | small |    V   |    V     | small A and R |\n",
        &hex::encode(&tv2.message)[60..],
        &hex::encode(&tv2.signature)[124..]
    ));
    vec.push(tv2); // passes cofactored, passes cofactorless

    // #1: canonical S, mixed R, small A
    let (_tv1, tv2) = non_zero_mixed_small().unwrap();
    info.append(format!(
        "| 1| ..{:} | ..{:} |  < L | small | mixed |    V   |    V     | small A only |\n",
        &hex::encode(&tv2.message)[60..],
        &hex::encode(&tv2.signature)[124..]
    ));
    vec.push(tv2); // passes cofactored, passes cofactorless

    // #2: canonical S, small R, mixed A
    let (_tv1, tv2) = non_zero_small_mixed().unwrap();
    info.append(format!(
        "| 2| ..{:} | ..{:} |  < L | mixed | small |    V   |    V     | small R only |\n",
        &hex::encode(&tv2.message)[60..],
        &hex::encode(&tv2.signature)[124..]
    ));
    vec.push(tv2); // passes cofactored, passes cofactorless

    // #3-4: canonical S, mixed R, mixed A
    let (tv1, tv2) = non_zero_mixed_mixed().unwrap();
    info.append(format!("| 3| ..{:} | ..{:} |  < L | mixed | mixed |    V   |    V     | succeeds unless full-order is checked |\n", &hex::encode(&tv2.message)[60..], &hex::encode(&tv2.signature)[124..]));
    vec.push(tv2); // passes cofactored, passes cofactorless
    info.append(format!(
        "| 4| ..{:} | ..{:} |  < L | mixed | mixed |    V   |    X     |  |\n",
        &hex::encode(&tv1.message)[60..],
        &hex::encode(&tv1.signature)[124..]
    ));
    vec.push(tv1); // passes cofactored, fails cofactorless

    // #5 Prereduce scalar which fails cofactorless
    let tv1 = pre_reduced_scalar();
    info.append(format!("| 5| ..{:} | ..{:} |  < L | mixed |   L   |    V*  |    X     | fails cofactored iff (8h) prereduced |\n", &hex::encode(&tv1.message)[60..], &hex::encode(&tv1.signature)[124..]));
    vec.push(tv1);

    // #6 Large S
    let tv1 = large_s().unwrap();
    info.append(format!(
        "| 6| ..{:} | ..{:} |  > L |   L   |   L   |    V   |    V     |  |\n",
        &hex::encode(&tv1.message)[60..],
        &hex::encode(&tv1.signature)[124..]
    ));
    vec.push(tv1);

    // #7 Large S beyond the high bit checks (i.e. non-canonical representation)
    let tv1 = really_large_s().unwrap();
    info.append(format!(
        "| 7| ..{:} | ..{:} | >> L |   L   |   L   |    V   |    V     |  |\n",
        &hex::encode(&tv1.message)[60..],
        &hex::encode(&tv1.signature)[124..]
    ));
    vec.push(tv1);

    // #8-9 Non canonical R
    let mut tv_vec = non_zero_small_non_canonical_mixed().unwrap();
    assert!(tv_vec.len() == 2);
    info.append(format!("| 8| ..{:} | ..{:} |  < L | mixed | small*|    V   |    V     | non-canonical R, reduced for hash |\n", &hex::encode(&tv_vec[0].message)[60..], &hex::encode(&tv_vec[0].signature)[124..]));
    info.append(format!("| 9| ..{:} | ..{:} |  < L | mixed | small*|    V   |    V     | non-canonical R, not reduced for hash |\n", &hex::encode(&tv_vec[1].message)[60..], &hex::encode(&tv_vec[1].signature)[124..]));
    vec.append(&mut tv_vec);

    // #10-11 Non canonical A
    let mut tv_vec = non_zero_mixed_small_non_canonical().unwrap();
    assert!(tv_vec.len() == 2);
    info.append(format!("|10| ..{:} | ..{:} |  < L | small*| mixed |    V   |    V     | non-canonical A, reduced for hash |\n", &hex::encode(&tv_vec[0].message)[60..], &hex::encode(&tv_vec[0].signature)[124..]));
    info.append(format!("|11| ..{:} | ..{:} |  < L | small*| mixed |    V   |    V     | non-canonical A, not reduced for hash |\n", &hex::encode(&tv_vec[1].message)[60..], &hex::encode(&tv_vec[1].signature)[124..]));
    vec.append(&mut tv_vec);

    // print!("{}", info.string().unwrap());

    vec
}
