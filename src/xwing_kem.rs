use alloc::{string::ToString, vec::Vec};
use hpke_rs_crypto::{error::Error, HpkeCrypto};
use kem::Decapsulate;
use x_wing::{
    CIPHERTEXT_SIZE, DECAPSULATION_KEY_SIZE, ENCAPSULATION_KEY_SIZE, ENCAP_RANDOMNESS_SIZE,
};

use crate::kem::{PrivateKey, PublicKey};

pub(super) fn encaps(pk_r: &[u8], randomness: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let pk_r =
        <[u8; ENCAPSULATION_KEY_SIZE]>::try_from(pk_r).map_err(|_| Error::KemInvalidPublicKey)?;
    let randomness = <[u8; ENCAP_RANDOMNESS_SIZE]>::try_from(randomness)
        .map_err(|_| Error::InsufficientRandomness)?;

    let pk_r = x_wing::EncapsulationKey::from(&pk_r);
    let (enc, zz) = pk_r
        .encapsulate_derand(randomness)
        .map_err(|_| Error::CryptoLibraryError("KEM encapsulation failed".to_string()))?;

    Ok((zz.to_vec(), enc.as_bytes().to_vec()))
}

pub(super) fn decaps(enc: &[u8], sk_r: &[u8]) -> Result<Vec<u8>, Error> {
    let sk_r =
        <[u8; DECAPSULATION_KEY_SIZE]>::try_from(sk_r).map_err(|_| Error::KemInvalidSecretKey)?;
    let sk_r = x_wing::DecapsulationKey::from(sk_r);

    let ciphertext = <[u8; CIPHERTEXT_SIZE]>::try_from(enc).map_err(|_| Error::DecapFailed)?;

    let ciphertext = x_wing::Ciphertext::from(&ciphertext);

    sk_r.decapsulate(&ciphertext)
        .map_err(|_| Error::CryptoLibraryError("KEM decapsulation failed".to_string()))
        .map(|zz| zz.to_vec())
}

pub(super) fn key_gen<Crypto: HpkeCrypto>(
    prng: &mut Crypto::HpkePrng,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (sk, pk) = x_wing::generate_key_pair(prng);
    Ok((sk.as_bytes().to_vec(), pk.as_bytes().to_vec()))
}

pub(super) fn derive_key_pair(ikm: &[u8]) -> Result<(PublicKey, PrivateKey), Error> {
    let randomness =
        <[u8; DECAPSULATION_KEY_SIZE]>::try_from(ikm).map_err(|_| Error::InsufficientRandomness)?;
    let (sk, pk) = x_wing::generate_key_pair_derand(randomness);
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}
