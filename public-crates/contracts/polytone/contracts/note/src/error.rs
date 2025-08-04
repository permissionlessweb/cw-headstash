use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    Handshake(#[from] polytone::handshake::error::HandshakeError),

    #[error("contract is already paired with port ({pair_port}) on connection ({pair_connection}), got port ({suggested_port}) on connection ({suggested_connection})")]
    AlreadyPaired {
        suggested_connection: String,
        suggested_port: String,
        pair_connection: String,
        pair_port: String,
    },

    #[error("contract has no pair, establish a channel with a voice module to create one")]
    NoPair,

    #[error("ERR_GAS_NEEDED can't be higher then BLOCK_MAX_GAS")]
    GasLimitsMismatch,

    #[error("channel sequence number overflow, to fix: the contract admin may migrate to close and reopen the channel")]
    SequenceOverflow,

    #[error("CwGlobExists")]
    CwGlobExists {},

    #[error("NoSnip120uParamsSet")]
    NoSnip120uParamsSet {},

    #[error("SetSnip120uCodeError")]
    SetSnip120uCodeError {},

    #[error("SetHeadstashCodeError")]
    SetHeadstashCodeError {},

    #[error("SetHeadstashAddrError.")]
    SetHeadstashAddrError {},

    #[error("SetInitSnip120uError.")]
    SetInitSnip120uError {},

    #[error("Snip120uAddrAlreadySet")]
    Snip120uAddrAlreadySet {},

    #[error("snip code-id not set")]
    NoSnipCodeId {},

    #[error("headstash code-id not set.")]
    NoHeadstashCodeId {},

    #[error("NoSnip120uContract")]
    NoSnip120uContract {},

    #[error("snip token not set")]
    NoSnipContractAddr {},

    #[error("BadContractId")]
    BadContractId {},

    #[error("AuthzGranteeExists")]
    AuthzGranteeExists {},

    #[error("headstash contract addr not set.")]
    NoHeadstashContract {},

    #[error("not a valid feegranter address")]
    NotValidFeegranter {},

    #[error("Unauthorized")]
    Unauthorized {},

}
