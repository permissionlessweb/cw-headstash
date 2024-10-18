use std::num::ParseIntError;

use cosmwasm_std::{Instantiate2AddressError, StdError};
use thiserror::Error;

use cw_ica_controller::types::ContractError as CwIcaControllerError;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("error when computing the instantiate2 address: {0}")]
    Instantiate2AddressError(#[from] Instantiate2AddressError),

    #[error("error : {0}")]
    CwIcaControllerError(#[from] CwIcaControllerError),

    #[error("SubMsgError")]
    SubMsgError {},
    
    #[error("no coin sent matches the expected coins to be sent")]
    NoCoinSentMatchesHeadstashParams {},

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

    #[error("snip token not set")]
    NoSnipContractAddr {},

    #[error("headstash code-id not set.")]
    NoHeadstashCodeId {},

    #[error("headstash contract addr not set.")]
    NoHeadstashContract {},

    #[error("ica information is not set")]
    IcaInfoNotSet {},

    #[error("this contract must have an owner")]
    OwnershipCannotBeRenounced,

    #[error("{0}")]
    OwnershipError(#[from] cw_ownable::OwnershipError),

    #[error("{0}")]
    ParseIntError(#[from] ParseIntError),

    #[error("unauthorized")]
    Unauthorized {},

    #[error("InvalidAttribute")]
    InvalidAttribute {},

    #[error("InvalidEvent")]
    InvalidEvent {},
}
