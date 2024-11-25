use std::num::ParseIntError;

use cosmrs::proto::prost::EncodeError;
use cosmwasm_std::{Instantiate2AddressError, StdError};
use thiserror::Error;

use cw_ica_controller::types::ContractError as CwIcaControllerError;

#[derive(Error,Debug)]
pub enum ContractError {

    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    EncodeError(#[from] EncodeError),

    #[error("error when computing the instantiate2 address: {0}")]
    Instantiate2AddressError(#[from] Instantiate2AddressError),

    #[error("error : {0}")]
    CwIcaControllerError(#[from] CwIcaControllerError),
    
    #[error("submessage error cw-ica-owner : {0}")]
    SubMsgError(String),

    #[error("no coin sent matches the expected coins to be sent")]
    NoCoinSentMatchesHeadstashParams {},

    #[error("NoSnip120uParamsSet")]
    NoSnip120uParamsSet {},

    #[error("SetSnip120uCodeError")]
    SetSnip120uCodeError {},

    #[error("SetHeadstashCodeError")]
    SetHeadstashCodeError {},

    #[error("NoSnip120uContract")]
    NoSnip120uContract {},

    #[error("Snip120uAddrAlreadySet")]
    Snip120uAddrAlreadySet {},

    #[error("ica information is not set, headstash")]
    NoIcaInfo {},

    #[error("bad headstash coin")]
    BadHeadstashCoin,

    #[error("CallbackError")]
    CallbackError {},

    #[error("not a valid feegranter address")]
    NotValidFeegranter {},

    #[error("headstash information is not set")]
    NoHeadstashInfo {},

    #[error("snip code-id not set")]
    NoSnipCodeId {},

    #[error("snip code hash not set")]
    NoSnip120uCodeHash {},

    #[error("snip token not set")]
    NoSnipContractAddr {},

    #[error("headstash code-id not set.")]
    NoHeadstashCodeId {},

    #[error("headstash contract addr not set.")]
    NoHeadstashContract {},

    #[error("SetHeadstashAddrError.")]
    SetHeadstashAddrError {},

    #[error("SetInitSnip120uError.")]
    SetInitSnip120uError {},

    #[error("ica information is not set")]
    IcaInfoNotSet {},

    #[error("AuthzGranteeExists")]
    AuthzGranteeExists {},

    #[error("this contract must have an owner")]
    OwnershipCannotBeRenounced,

    #[error("{0}")]
    OwnershipError(#[from] cw_ownable::OwnershipError),

    #[error("{0}")]
    ParseIntError(#[from] ParseIntError),

    #[error("unauthorized")]
    Unauthorized {},

    #[error("missing attribute : {0}")]
    MissingAttribute(String),

    #[error("InvalidEvent")]
    InvalidEvent {},
    #[error("BadStoreHeadstashCodeResponse")]
    BadStoreHeadstashCodeResponse {},
    
    #[error("BadStoreSnip120uCodeResponse")]
    BadStoreSnip120uCodeResponse {},

    #[error("BadContractid")]
    BadContractid {},
    
    #[error("BadReply")]
    BadReply {},
    
    #[error("CwGlobExists")]
    CwGlobExists {},

    #[error("IcaAccountExists")]
    IcaAccountExists {},
}
