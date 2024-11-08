use cosmwasm_std::{CheckedFromRatioError, StdError};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    CheckedFromRatioError(#[from] CheckedFromRatioError),

    #[error("This headstash contract has not been set as an eligible minter yet.")]
    HeadstashNotSnip120uMinter {},

    #[error("It does not seem you are eligible for this headstash")]
    NotEligible {},

    #[error("You have already claimed your headstash, homie!")]
    AlreadyClaimed {},

    #[error("you cannot clawback the headstash, silly!")]
    ClawbackError {},

    #[error("Clawback was not setup for this one, playa!")]
    ClawbackUnavailable {},

    #[error("unauthorized")]
    Unauthorized {},

    // #[error("serde_json error")]
    // SerdeJSON(#[from] serde_json::Error),
    #[error("Unable to process bloom. Headstash signer does not match message sender.")]
    BloomMismatchSigner {},

    #[error("aint no bloomin happenin!")]
    BloomDisabled {},

    #[error("unable to process bloom. Either you have not claimed your headstash yet, you provided an invalid snip120u addr, or you are not eligible.")]
    BloomNotFound {},

    #[error(
        "incorrect denom length. the maximum length is 36 bytes, the same length as ibc-denoms"
    )]
    BloomIncorrectStringLength {},

    #[error("The number of msgs you have set to granularize your bloomMsg into is greater than the maximum set by contract owner.")]
    BloomTooManyGrains {},

    #[error("Provide atleast 1 msg to process.")]
    BloomNotEnoughGrains {},

    #[error("Invalid batch value.")]
    InvalidBatchAmount {},

    #[error(
        "the total amount specificed in you granular messages does not equal the total amount set"
    )]
    BloomTotalError {},

    #[error("Blooming for this token has already begun! There is no current support to update or add additional bloom msgs for the same source token.If you would like this feature, lets make it happen :)")]
    BloomDuplicate {},

    #[error("Contract got an unexpected Reply")]
    UnexpectedReply(),

    #[error("Duplicate snip120u were provided")]
    DuplicateSnip120u(),

    #[error("FromUtf8Error: {0}")]
    JsonSerde(#[from] std::string::FromUtf8Error),

    // #[error("json_serde_wasm serialization error: {0}")]
    // JsonWasmSerialize(#[from] serde_json_wasm::ser::Error),
    #[error("json_serde_wasm deserialization error: {0}")]
    JsonWasmDeserialize(#[from] serde_json_wasm::de::Error),

    #[error("prost encoding error: {0}")]
    ProstEncodeError(#[from] cosmos_sdk_proto::prost::EncodeError),

    #[error("prost decoding error: {0}")]
    ProstDecodeError(#[from] cosmos_sdk_proto::prost::DecodeError),

    // #[error("semver parse error: {0}")]
    // SemverError(#[from] semver::Error),
    #[error("Not Owner")]
    OwnershipError(),

    // #[error("{0}")]
    // BufanyError(#[from] anybuf::BufanyError),
    #[error("this contract must have an owner")]
    OwnershipCannotBeRenounced,

    #[error("invalid migration version: expected {expected}, got {actual}")]
    InvalidMigrationVersion { expected: String, actual: String },

    #[error("invalid channel ordering")]
    InvalidChannelOrdering,

    #[error("invalid host port")]
    InvalidHostPort,

    #[error("invalid controller port")]
    InvalidControllerPort,

    #[error("invalid interchain accounts version: expected {expected}, got {actual}")]
    InvalidVersion { expected: String, actual: String },

    #[error("MsgChannelOpenInit is not allowed")]
    ChannelOpenInitNotAllowed,

    #[error("MsgChannelCloseInit is not allowed")]
    ChannelCloseInitNotAllowed,

    #[error("codec is not supported: unsupported codec format {0}")]
    UnsupportedCodec(String),

    #[error("invalid interchain account address")]
    InvalidIcaAddress,

    #[error("unsupported transaction type {0}")]
    UnsupportedTxType(String),

    #[error("invalid connection")]
    InvalidConnection,

    #[error("unknown data type: {0}")]
    UnknownDataType(String),

    #[error("active channel already set for this contract")]
    ActiveChannelAlreadySet,

    #[error("invalid channel in contract state")]
    InvalidChannelInContractState,

    #[error("interchain account information is not set")]
    IcaInfoNotSet,

    #[error("no channel init options are provided to the contract")]
    NoChannelInitOptions,

    #[error("invalid channel status: expected {expected}, got {actual}")]
    InvalidChannelStatus { expected: String, actual: String },

    #[error("no callback address is set for the contract")]
    NoCallbackAddress,

    #[error("unsupported packet encoding: {0}")]
    UnsupportedPacketEncoding(String),

    #[error("empty response: {0}")]
    EmptyResponse(String),

    #[error("the msg you sent contained an empty value!")]
    EmptyValue,

    #[error("Invalid snip120u!")]
    InvalidSnip120u,

    #[error("unknown reply id: {0}")]
    UnknownReplyId(u64),
}
