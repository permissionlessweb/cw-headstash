use cosmwasm_std::{Api,  StdError, StdResult};
use secret_toolkit::crypto::secp256k1::PublicKey;
use sha2::Digest;
use sha3::Keccak256;

#[allow(dead_code)]
pub const VERSION: &str = "crypto-verify-v2";

/// Get the recovery param from the value `v` when no chain ID for replay protection is used.
///
/// This is needed for chain-agnostig aignatures like signed text.
///
/// See [EIP-155] for how `v` is composed.
///
/// [EIP-155]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
pub fn get_recovery_param(v: u8) -> StdResult<u8> {
    match v {
        27 => Ok(0),
        28 => Ok(1),
        _ => Err(StdError::generic_err("Values of v other than 27 and 28 not supported. Replay protection (EIP-155) cannot be used here."))
    }
}

/// Returns a raw 20 byte Ethereum address
pub fn ethereum_address_raw(pubkey: &[u8]) -> StdResult<[u8; 20]> {
    let (tag, data) = match pubkey.split_first() {
        Some(pair) => pair,
        None => return Err(StdError::generic_err("Public key must not be empty")),
    };
    if *tag != 0x04 {
        return Err(StdError::generic_err("Public key must start with 0x04"));
    }
    if data.len() != 64 {
        return Err(StdError::generic_err("Public key must be 65 bytes long"));
    }

    let hash = Keccak256::digest(data);
    Ok(hash[hash.len() - 20..].try_into().unwrap())
}

pub fn decode_address(input: &str) -> StdResult<[u8; 20]> {
    if input.len() != 42 {
        return Err(StdError::generic_err(
            "Ethereum address must be 42 characters long",
        ));
    }
    if !input.starts_with("0x") {
        return Err(StdError::generic_err("Ethereum address must start with 0x"));
    }
    let data = hex::decode(&input[2..]).map_err(|_| StdError::generic_err("hex decoding error"))?;
    Ok(data.try_into().unwrap())
}

pub fn verify_ethereum_text(
    api: &dyn Api,
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
    let calculated_pubkey = api.secp256k1_recover_pubkey(&hash, rs, recovery)?;

    // Deserialize the uncompressed public key
    let uncompressed_public_key = PublicKey::parse(&calculated_pubkey)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    let calculated_address = ethereum_address_raw(&uncompressed_public_key.serialize())?;
    if signer_address != calculated_address {
        return Ok(false);
    }
    let result = api.secp256k1_verify(&hash, rs, &calculated_pubkey);
    match result {
        Ok(verifies) => Ok(verifies),
        Err(err) => Err(err.into()),
    }
}
