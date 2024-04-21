use cosmwasm_std::{Deps, StdError, StdResult};
use secret_toolkit::crypto::secp256k1::PublicKey;
use sha2::Digest;
use sha3::Keccak256;

use crate::{decode_address, ethereum_address_raw, get_recovery_param};

#[allow(dead_code)]
pub const VERSION: &str = "crypto-verify-v2";

// TODO CHANGE TO VERIFY
pub fn verify_ethereum_text(
    deps: Deps,
    message: &str,
    signature: &[u8],
    signer_address: &str,
) -> StdResult<bool> {
    let signer_address = decode_address(signer_address)?;

    // Hashing
    let mut hasher = Keccak256::new();
    hasher.update(format!("\x19Ethereum Signed Message:\n{}", message.len()));
    hasher.update(message);
    let hash = hasher.finalize();

    // Decompose signature
    let (v, rs) = match signature.split_last() {
        Some(pair) => pair,
        None => return Err(StdError::generic_err("Signature must not be empty")),
    };
    let recovery = get_recovery_param(*v)?;

    // Verification
    let calculated_pubkey = deps.api.secp256k1_recover_pubkey(&hash, rs, recovery)?;

    // Deserialize the uncompressed public key
    let uncompressed_public_key = PublicKey::parse(&calculated_pubkey)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    let calculated_address = ethereum_address_raw(&uncompressed_public_key.serialize())?;
    if signer_address != calculated_address {
        return Ok(false);
    }
    let result = deps.api.secp256k1_verify(&hash, rs, &calculated_pubkey);
    match result {
        Ok(verifies) => Ok(verifies),
        Err(err) => Err(err.into()),
    }
}
