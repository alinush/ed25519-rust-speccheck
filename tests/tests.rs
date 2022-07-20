#[cfg(test)]
mod tests {
    use anyhow::{anyhow, Result};
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::{scalar::Scalar, traits::IsIdentity};

    use ed25519_dalek::{PublicKey, Signature, Verifier};
    use ed25519_speccheck::{
        algorithm2, compute_hram, deserialize_point, new_rng, serialize_signature,
        test_vectors::{generate_test_vectors, TestVector},
        verify_cofactored, verify_cofactorless, EIGHT_TORSION,
    };
    use ed25519_zebra::{Signature as ZSignature, VerificationKey as ZPublicKey};
    use rand::RngCore;
    use ring::signature;
    use std::convert::TryFrom;
    use std::ops::Neg;

    fn unpack_test_vector_dalek(t: &TestVector) -> (PublicKey, Signature) {
        let pk = PublicKey::from_bytes(&t.pub_key[..]).unwrap();
        let sig = Signature::try_from(&t.signature[..]).unwrap();
        (pk, sig)
    }

    fn unpack_test_vector_hacl(
        t: &TestVector,
    ) -> (hacl_star::ed25519::PublicKey, hacl_star::ed25519::Signature) {
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&t.signature[..]);

        let pk = hacl_star::ed25519::PublicKey(t.pub_key);
        let sig = hacl_star::ed25519::Signature(sig_bytes);
        (pk, sig)
    }

    fn unpack_test_vector_zebra(t: &TestVector) -> (ZPublicKey, ZSignature) {
        let pk = ZPublicKey::try_from(&t.pub_key[..]).unwrap();
        let sig = ZSignature::try_from(&t.signature[..]).unwrap();
        (pk, sig)
    }

    fn ring_verify(t: &TestVector) -> Result<()> {
        let pk = untrusted::Input::from(&t.pub_key[..]);
        let sig = untrusted::Input::from(&t.signature[..]);
        let msg = untrusted::Input::from(&t.message[..]);
        <signature::EdDSAParameters as signature::VerificationAlgorithm>::verify(
            &signature::ED25519,
            pk,
            msg,
            sig,
        )
        .map_err(|_| anyhow!("signature verification failed"))
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_CGN20_algorithm2() {
        let vec = generate_test_vectors();

        print!("\n|[CGN20e] Alg.2 |");
        for tv in vec.iter() {
            let pk = match algorithm2::deserialize_pk(&tv.pub_key) {
                Ok(pk) => pk,
                Err(_) => {
                    print!(" X |");
                    continue;
                }
            };

            let (s, R) = match algorithm2::deserialize_signature(&tv.signature) {
                Ok(sR) => sR,
                Err(_) => {
                    print!(" X |");
                    continue;
                }
            };

            if algorithm2::verify_signature(&s, &R, &tv.message, &pk) {
                print!(" V |");
            } else {
                print!(" X |");
            }
        }
        println!();
    }

    #[test]
    fn test_diem() {
        let vec = generate_test_vectors();

        print!("\n|libra-crypto   |");
        for tv in vec.iter() {
            let pk = match diem_crypto::ed25519::Ed25519PublicKey::try_from(&tv.pub_key[..]) {
                Ok(pk) => pk,
                Err(_e) => {
                    print!(" X |");
                    continue;
                }
            };
            let sig = match diem_crypto::ed25519::Ed25519Signature::try_from(&tv.signature[..]) {
                Ok(sig) => sig,
                Err(_e) => {
                    print!(" X |");
                    continue;
                }
            };
            match diem_crypto::traits::Signature::verify_arbitrary_msg(&sig, &tv.message[..], &pk) {
                Ok(_v) => print!(" V |"),
                Err(_e) => print!(" X |"),
            }
        }
        println!();
    }

    #[test]
    fn test_aptos() {
        let vec = generate_test_vectors();

        print!("\n|aptos-crypto   |");
        for tv in vec.iter() {
            if !test_aptos_helper(tv) {
                continue
            }
        }
        println!();
    }

    fn test_aptos_helper(tv: &TestVector) -> bool {
        let pk = match aptos_crypto::ed25519::Ed25519PublicKey::try_from(&tv.pub_key[..]) {
            Ok(pk) => pk,
            Err(_e) => {
                print!(" X |");
                return false;
            }
        };
        let sig = match aptos_crypto::ed25519::Ed25519Signature::try_from(&tv.signature[..]) {
            Ok(sig) => sig,
            Err(_e) => {
                print!(" X |");
                return false;
            }
        };

        match aptos_crypto::traits::Signature::verify_arbitrary_msg(&sig, &tv.message[..], &pk)
        {
            Ok(_v) => {
                print!(" V |");
            },
            Err(_e) => {
                print!(" X |");
                return false;
            }
        }

        return true;
    }

    #[test]
    fn test_aptos_strong() {
        let vec = generate_test_vectors();

        print!("\n|aptos-crypto-st|");
        for tv in vec.iter() {
            // We are just manually checking the pubkey encoding is canonical
            if !algorithm2::is_canonical_point_encoding(&tv.pub_key) {
                print!(" X |");
                continue;
            }

            // We are just manually checking the signature's R encoding is canonical
            if !algorithm2::is_canonical_point_encoding(&tv.signature[..32]) {
                print!(" X |");
                continue;
            }

            if !test_aptos_helper(tv) {
                continue;
            }
        }
        println!();
    }

    #[test]
    fn test_hacl() {
        let vec = generate_test_vectors();

        print!("\n|Hacl*          |");
        for tv in vec.iter() {
            let (pk, sig) = unpack_test_vector_hacl(tv);
            if pk.verify(&tv.message[..], &sig) {
                print!(" V |");
            } else {
                print!(" X |");
            }
        }
        println!();
    }

    #[test]
    fn test_dalek() {
        let vec = generate_test_vectors();

        print!("\n|Dalek          |");
        for tv in vec.iter() {
            match Signature::try_from(&tv.signature[..]) {
                Ok(_v) => {}
                Err(_e) => {
                    print!(" X |");
                    continue;
                }
            }

            let (pk, sig) = unpack_test_vector_dalek(tv);
            match pk.verify(&tv.message[..], &sig) {
                Ok(_v) => print!(" V |"),
                Err(_e) => print!(" X |"),
            }
        }
        println!();
    }

    #[test]
    fn test_dalek_verify_strict() {
        let vec = generate_test_vectors();

        print!("\n|Dalek strict   |");
        for tv in vec.iter() {
            match Signature::try_from(&tv.signature[..]) {
                Ok(_v) => {}
                Err(_e) => {
                    print!(" X |");
                    continue;
                }
            }

            let (pk, sig) = unpack_test_vector_dalek(tv);
            match pk.verify_strict(&tv.message[..], &sig) {
                Ok(_v) => print!(" V |"),
                Err(_e) => print!(" X |"),
            }
        }
        println!();
    }

    #[test]
    fn test_boringssl() {
        let vec = generate_test_vectors();

        print!("\n|BoringSSL      |");
        for tv in vec.iter() {
            match ring_verify(tv) {
                Ok(_v) => print!(" V |"),
                Err(_e) => print!(" X |"),
            }
        }
        println!();
    }

    #[test]
    fn test_zebra() {
        let vec = generate_test_vectors();

        print!("\n|Zebra          |");
        for tv in vec.iter() {
            match Signature::try_from(&tv.signature[..]) {
                Ok(_v) => {}
                Err(_e) => {
                    print!(" X |");
                    continue;
                }
            }

            let (pk, sig) = unpack_test_vector_zebra(tv);
            match pk.verify(&sig, &tv.message[..]) {
                Ok(_v) => print!(" V |"),
                Err(_e) => print!(" X |"),
            }
        }
        println!();
    }

    #[test]
    fn test_repudiation_dalek() {
        // Pick a random Scalar
        let mut rng = new_rng();
        let mut scalar_bytes = [0u8; 32];
        rng.fill_bytes(&mut scalar_bytes);
        let s = Scalar::from_bytes_mod_order(scalar_bytes);
        debug_assert!(s.is_canonical());
        debug_assert!(s != Scalar::zero());

        let r0 = s * ED25519_BASEPOINT_POINT;
        // Pick a torsion point of order 2
        let pub_key = deserialize_point(&EIGHT_TORSION[4]).unwrap();
        let r = r0 + pub_key.neg();

        let message1 = b"Send 100 USD to Alice";
        let message2 = b"Send 100000 USD to Alice";

        debug_assert!(
            (pub_key.neg() + compute_hram(message1, &pub_key, &r) * pub_key).is_identity()
        );
        debug_assert!(
            (pub_key.neg() + compute_hram(message2, &pub_key, &r) * pub_key).is_identity()
        );

        debug_assert!(verify_cofactored(message1, &pub_key, &(r, s)).is_ok());
        debug_assert!(verify_cofactorless(message1, &pub_key, &(r, s)).is_ok());
        debug_assert!(verify_cofactored(message2, &pub_key, &(r, s)).is_ok());
        debug_assert!(verify_cofactorless(message2, &pub_key, &(r, s)).is_ok());

        println!(
            "Small pk breaks non-repudiation:\n\
             \"pub_key\": \"{}\",\n\
             \"signature\": \"{}\",\n\
             \"message1\": \"{}\",\n\
             \"message2\": \"{}\"",
            hex::encode(&pub_key.compress().as_bytes()),
            hex::encode(&serialize_signature(&r, &s)),
            hex::encode(&message1),
            hex::encode(&message2),
        );

        let signature = serialize_signature(&r, &s);
        let pk = PublicKey::from_bytes(&pub_key.compress().as_bytes()[..]).unwrap();
        let sig = Signature::try_from(&signature[..]).unwrap();
        debug_assert!(pk.verify(message1, &sig).is_ok());
        debug_assert!(pk.verify(message2, &sig).is_ok());
    }
}
