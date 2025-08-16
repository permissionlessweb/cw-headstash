use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{
    Binary, CosmosMsg, Empty, Env, MessageInfo, QuerierWrapper, QueryRequest, Storage, Uint64,
};

use headstash_public::state::{Headstash, HeadstashParams, Lhsm};
use polytone::{
    callbacks::{CallbackMessage, CallbackRequest},
    headstash::{errors::ContractError, HeadstashCallback},
};

#[cw_serde]
pub struct InstantiateMsg {
    /// This contract pairs with the first voice module that a relayer
    /// connects it with, or the pair specified here. Once it has a
    /// pair, it will never handshake with a different voice module,
    /// even after channel closure. This ensures that there will only
    /// ever be one voice for every note.
    pub pair: Option<Pair>,

    /// The max gas allowed in a transaction. When returning callbacks
    /// the module will use this to calculate the amount of gas to
    /// save for handling a callback error. This protects from
    /// callbacks that run out of gas preventing ACKs or timeouts from
    /// being returned.
    ///
    /// The contract admin can update with `MigrateMsg::WithUpdate`.
    pub block_max_gas: Uint64,

    pub headstash_params: HeadstashParams,
}

#[cw_serde]
#[cfg_attr(feature = "interface", derive(cw_orch::ExecuteFns))] // cw-orch automatic
pub enum ExecuteMsg {
    /// Performs the requested queries on the voice chain and returns
    /// a callback of Vec<QuerierResult>, or ACK-FAIL if unmarshalling
    /// any of the query requests fails.
    Query {
        msgs: Vec<QueryRequest<Empty>>,
        callback: CallbackRequest,
        timeout_seconds: Uint64,
    },
    /// Executes the requested messages on the voice chain on behalf
    /// of the note chain sender. Message receivers can return data in
    /// their callbacks by calling `set_data` on their `Response`
    /// object. Optionally, returns a callback of `Vec<Callback>` where
    /// index `i` corresponds to the callback for `msgs[i]`.
    ///
    /// Accounts are created on the voice chain after the first call
    /// to execute by the local address. To create an account, but
    /// perform no additional actions, pass an empty list to
    /// `msgs`. Accounts are queryable via the `RemoteAddress {
    /// local_address }` query after they have been created.
    Execute {
        headstash_msg: HeadstashNote,
        callback: Option<CallbackRequest>,
        timeout_seconds: Uint64,
    },
    /// Entrypoint for Headstash callbacks from actions on the voice chain on behalf
    /// of the headstash-note chain sender.
    HeadstashCallBack(HeadstashCallback),
    Callback(CallbackMessage),
}

#[cw_serde]
#[derive(QueryResponses)]
#[cfg_attr(feature = "interface", derive(cw_orch::QueryFns))] // cw-orch automatic
pub enum QueryMsg {
    /// This channel this note is currently connected to, or none if
    /// no channel is connected.
    #[returns(Option<String>)]
    ActiveChannel,
    /// The contract's corresponding voice on a remote chain.
    #[returns(Option<Pair>)]
    Pair,
    /// Returns the remote address for the provided local address. If
    /// no account exists, returns `None`. An account can be created
    /// by calling `ExecuteMsg::Execute` with the sender being
    /// `local_address`.
    #[returns(Option<String>)]
    RemoteAddress { local_address: String },
    /// Currently set gas limit
    #[returns(Uint64)]
    BlockMaxGas,
}

/// This contract's voice. There is one voice per note, and many notes
/// per voice.
#[cw_serde]
pub struct Pair {
    pub connection_id: String,
    pub remote_port: String,
}

#[cw_serde]
pub enum MigrateMsg {
    /// Updates the contract's configuration. To update the config
    /// without updating the code, migrate to the same code ID.
    WithUpdate { block_max_gas: Uint64 },
}

#[cw_serde]
pub enum HeadstashNote {
    UploadHeadstashOnSecret {},
    // SetCwGlob {
    //     /// The storage key set in cw-glob. defaults enabled are either `snip120u` or `cw-headstash`
    //     cw_glob: String,
    // },
    // SetHeadstashCodeId {
    //     code_id: u64,
    // },
    // SetSnip120uCodeId {
    //     code_id: u64,
    // },
    // SetHeadstashAddr {
    //     addr: String,
    // },
    // SetSnip120uAddr {
    //     denom: String,
    //     addr: String,
    // },
    // FundHeadstash {},
    CreateSnips {},
    CreateHeadstash {},
    ConfigureSnip120uMinter {},
    AddHeadstashes {
        to_add: Vec<Headstash>,
    },
    AuthorizeFeeGrants {
        to_grant: Vec<String>,
        owner: Option<String>,
    },
    AuthzDeployer {
        grantee: String,
    },
    FundHeadstash {},
    /// Generic action on destination chain. Will trigger default polytone workflow.
    GenericMsg {
        msgs: Vec<CosmosMsg>,
    },
}

impl HeadstashNote {
    pub fn to_cosmos_msgs(
        &self,
        env: &Env,
        storage: &mut dyn Storage,
        info: MessageInfo,
        querier: QuerierWrapper,
    ) -> Result<(Lhsm, Vec<CosmosMsg<Empty>>), ContractError> {
        Ok(match self {
            HeadstashNote::UploadHeadstashOnSecret {} => (
                Lhsm::Ibc,
                vec![polytone::headstash::upload_contract_on_secret(
                    querier, storage, &info,
                )?],
            ),
            HeadstashNote::CreateSnips {} => (
                Lhsm::Ibc,
                polytone::headstash::create_snip120u_contract(storage, &info)?,
            ),
            HeadstashNote::CreateHeadstash {} => (
                Lhsm::Ibc,
                polytone::headstash::create_headstash_contract(storage, &info)?,
            ),
            HeadstashNote::ConfigureSnip120uMinter {} => (
                Lhsm::Ibc,
                polytone::headstash::authorize_headstash_as_snip_minter(storage, &info)?,
            ),
            HeadstashNote::AddHeadstashes { to_add } => (
                Lhsm::Ibc,
                polytone::headstash::add_headstash_claimers(storage, to_add, &info)?,
            ),
            HeadstashNote::AuthorizeFeeGrants { to_grant, .. } => (
                Lhsm::Ibc,
                polytone::headstash::authorize_feegrants(storage, &info, to_grant)?,
            ),
            HeadstashNote::AuthzDeployer { grantee } => (
                Lhsm::Ibc,
                polytone::headstash::grant_authz_for_deployer(storage, &info, grantee)?,
            ),
            HeadstashNote::FundHeadstash {} => (
                Lhsm::Local,
                polytone::headstash::fund_headstash(
                    storage,
                    &env.contract.address,
                    info.funds,
                    env.block.time,
                )?,
            ),
            HeadstashNote::GenericMsg { msgs } => (Lhsm::Callback, msgs.clone()),
        })
    }

    /// Assign a unique u64 ID to each variant.
    ///  000 means we never should have a callback as this msg is being executed locally.
    pub const fn callback_digits(&self) -> u32 {
        match self {
            // HeadstashNote::SetCwGlob { .. } => 000,
            // HeadstashNote::SetHeadstashCodeId { .. } => 000,
            // HeadstashNote::SetSnip120uCodeId { .. } => 000,
            // HeadstashNote::SetHeadstashAddr { .. } => 000,
            // HeadstashNote::SetSnip120uAddr { .. } => 000,
            HeadstashNote::UploadHeadstashOnSecret {} => 101,
            HeadstashNote::CreateSnips {} => 202,
            HeadstashNote::CreateHeadstash {} => 303,
            HeadstashNote::ConfigureSnip120uMinter {} => 404,
            HeadstashNote::AddHeadstashes { .. } => 505,
            HeadstashNote::AuthorizeFeeGrants { .. } => 606,
            HeadstashNote::AuthzDeployer { .. } => 707,
            HeadstashNote::FundHeadstash {} => 808,
            HeadstashNote::GenericMsg { .. } => 909,
        }
    }

    pub fn to_callback_request(&self, env: &Env) -> Result<CallbackRequest, ContractError> {
        Ok(CallbackRequest {
            receiver: env.contract.address.to_string(),
            msg: Binary::new(vec![]), // empty as we can infer msg that triggered callback from headstash_digits. saves some bytes.
            headstash_digits: self.callback_digits(),
        })
    }
}
