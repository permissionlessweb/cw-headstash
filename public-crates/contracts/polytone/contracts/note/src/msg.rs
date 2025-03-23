use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{
    Addr, Api, CosmosMsg, Empty, Env, MessageInfo, QueryRequest, StdError, Storage, Uint128, Uint64,
};

use polytone::callbacks::CallbackRequest;

use crate::{
    error::ContractError,
    state::{bloom::BloomConfig, headstash::Headstash},
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
    #[cfg_attr(feature = "interface", fn_name("ibc_query"))]
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
    #[cfg_attr(feature = "interface", fn_name("ibc_execute"))]
    Execute {
        headstash_msg: HeadstashNote,
        callback: Option<CallbackRequest>,
        timeout_seconds: Uint64,
    },
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

/// Params for Headstash
#[cw_serde]
pub struct HeadstashParams {
    /// The contract addr for cw-glob on the native chain.
    pub cw_glob: Option<Addr>,
    /// The code ID of the snip120u contract, on Secret Network.
    pub snip120u_code_id: Option<u64>,
    /// The code hash of the snip120u contract, on Secret Network. Not optional for pre-deployment verification
    pub snip120u_code_hash: String,
    /// Code id of Headstash contract on Secret Network
    pub headstash_code_id: Option<u64>,
    /// Params defined by deployer for tokens included.
    pub token_params: Vec<HeadstashTokenParams>,
    /// Headstash contract address this contract is admin of.
    /// We save this address in the first callback msg sent during setup_headstash,
    /// and then use it to set as admin for snip120u of assets after 1st callback.
    pub headstash_addr: Option<String>,
    /// The wallet address able to create feegrant authorizations on behalf of this contract
    pub fee_granter: Option<String>,
    /// Enables reward multiplier for cw-headstash
    pub multiplier: bool,
    /// bloom config
    pub bloom_config: Option<BloomConfig>,
    pub headstash_init_config: HeadstashInitConfig,
}

#[cw_serde]
pub struct HeadstashInitConfig {
    pub claim_msg_plaintxt: String,
    pub end_date: Option<u64>,
    pub start_date: Option<u64>,
    pub random_key: String,
}

/// Params for Headstash Tokens
#[cw_serde]
pub struct HeadstashTokenParams {
    /// Name to use in snip120u state
    pub name: String,
    /// Symbol to use
    pub symbol: String,
    /// native token name
    pub native: String,
    /// ibc string on Secret
    pub ibc: String,
    /// snip20 addr on Secret
    pub snip_addr: Option<String>,
    /// Total amount for specific snip
    pub total: Uint128,
}

#[cw_serde]
pub enum HeadstashNote {
    SetCwGlob {
        /// The storage key set in cw-glob. defaults enabled are either `snip120u` or `cw-headstash`
        cw_glob: String,
    },
    SetContractOnSecret {
        cw_glob: Option<String>,
        wasm: String,
    },
    SetHeadstashCodeId {
        code_id: u64,
    },
    SetSnip120uCodeId {
        code_id: u64,
    },
    SetHeadstashAddr {
        addr: String,
    },
    SetSnip120uAddr {
        denom: String,
        addr: String,
    },
    CreateSnip120u {},
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
}

impl HeadstashNote {
    pub fn to_secret_msg(
        &self,
        env: &Env,
        storage: &mut dyn Storage,
        api: &dyn Api,
        info: MessageInfo,
    ) -> Result<Vec<CosmosMsg<Empty>>, ContractError> {
        let msgs: Vec<CosmosMsg<Empty>> = Vec::new();
        let _ = match self {
            HeadstashNote::SetCwGlob { cw_glob } => {
                crate::headstash::set_cw_glob(storage, api, &info, cw_glob)
            }
            HeadstashNote::SetContractOnSecret { cw_glob, wasm } => {
                crate::headstash::set_contract_on_secret(storage, api, &info, wasm, cw_glob)
            }
            HeadstashNote::SetHeadstashCodeId { code_id } => {
                crate::headstash::set_headstash_code_id_on_secret(storage, api, &info, *code_id)
            }
            HeadstashNote::SetSnip120uCodeId { code_id } => {
                crate::headstash::set_snip120u_code_id_on_secret(storage, api, &info, *code_id)
            }
            HeadstashNote::SetHeadstashAddr { addr } => {
                crate::headstash::set_headstash_addr(storage, api, &info, addr.to_string())
            }
            HeadstashNote::SetSnip120uAddr { denom, addr } => crate::headstash::set_snip120u_addr(
                storage,
                api,
                denom.to_string(),
                addr.to_string(),
            ),
            HeadstashNote::CreateSnip120u {} => {
                crate::headstash::create_snip120u_contract(storage, api, &info)
            }
            HeadstashNote::CreateHeadstash {} => {
                crate::headstash::create_headstash_contract(env, storage, api, &info)
            }
            HeadstashNote::ConfigureSnip120uMinter {} => {
                crate::headstash::authorize_headstash_as_snip_minter(storage, api, &info)
            }
            HeadstashNote::AddHeadstashes { to_add } => {
                crate::headstash::add_headstash_claimers(storage, api, to_add, &info)
            }
            HeadstashNote::AuthorizeFeeGrants { to_grant, owner } => {
                crate::headstash::authorize_feegrants(storage, api, &info, to_grant)
            }
            HeadstashNote::AuthzDeployer { grantee } => {
                crate::headstash::grant_authz_for_deployer(storage, api, &info, grantee)
            }
            HeadstashNote::FundHeadstash {} => crate::headstash::fund_headstash(storage, api),
            _ => Err(ContractError::Std(StdError::generic_err("unimplemented"))),
        };
        Ok(msgs)
    }
}
