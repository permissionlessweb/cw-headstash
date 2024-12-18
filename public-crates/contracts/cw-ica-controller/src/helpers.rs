//! This file contains helper functions for working with this contract from
//! external contracts.

// use schemars::JsonSchema;
// use serde::{Deserialize, Serialize};

use cosmwasm_std::{
    instantiate2_address, to_json_binary, Addr, Api, CosmosMsg, Env, QuerierWrapper, StdError,
    StdResult, WasmMsg,
};

use crate::types::{msg, state};

pub use cw_ica_controller_derive::ica_callback_execute; // re-export for use in macros

/// `CwIcaControllerContract` is a wrapper around Addr that provides helpers
/// for working with this contract.
// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct CwIcaControllerContract(pub Addr);

/// `CwIcaControllerCodeId` is a wrapper around u64 that provides helpers for
/// initializing this contract.
// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct CwIcaControllerCode(pub u64);

/// `CwIcaControllerContractQuerier` is a wrapper around [`QuerierWrapper`] that provides
/// helpers for querying this contract.
///
/// This can be constructed by [`CwIcaControllerContract::query`] or [`Self::new`].
pub struct CwIcaControllerContractQuerier<'a> {
    querier: &'a QuerierWrapper<'a>,
    addr: String,
}

impl CwIcaControllerContract {
    /// new creates a new [`CwIcaControllerContract`]
    #[must_use]
    pub const fn new(addr: Addr) -> Self {
        Self(addr)
    }

    /// addr returns the address of the contract
    #[must_use]
    pub fn addr(&self) -> Addr {
        self.0.clone()
    }

    /// `execute` creates a [`WasmMsg::Execute`] message targeting this contract,
    ///
    /// # Errors
    ///
    /// This function returns an error if the given message cannot be serialized
    pub fn execute(&self, msg: impl Into<msg::ExecuteMsg>) -> StdResult<CosmosMsg> {
        let msg = to_json_binary(&msg.into())?;
        Ok(WasmMsg::Execute {
            contract_addr: self.addr().into(),
            msg,
            funds: vec![],
        }
        .into())
    }

    /// `query` creates a new [`LightClientContractQuerier`] for this contract.
    #[must_use]
    pub fn query<'a>(&self, querier: &'a QuerierWrapper) -> CwIcaControllerContractQuerier<'a> {
        CwIcaControllerContractQuerier::new(querier, self.addr().into_string())
    }

    /// `update_admin` creates a [`WasmMsg::UpdateAdmin`] message targeting this contract
    pub fn update_admin(&self, admin: impl Into<String>) -> CosmosMsg {
        WasmMsg::UpdateAdmin {
            contract_addr: self.addr().into(),
            admin: admin.into(),
        }
        .into()
    }

    /// `clear_admin` creates a [`WasmMsg::ClearAdmin`] message targeting this contract
    #[must_use]
    pub fn clear_admin(&self) -> CosmosMsg {
        WasmMsg::ClearAdmin {
            contract_addr: self.addr().into(),
        }
        .into()
    }

    /// `migrate` creates a [`WasmMsg::Migrate`] message targeting this contract
    ///
    /// # Errors
    ///
    /// This function returns an error if the given message cannot be serialized
    pub fn migrate(
        &self,
        msg: impl Into<msg::MigrateMsg>,
        new_code_id: u64,
    ) -> StdResult<CosmosMsg> {
        let msg = to_json_binary(&msg.into())?;
        Ok(WasmMsg::Migrate {
            contract_addr: self.addr().into(),
            new_code_id,
            msg,
        }
        .into())
    }
}

impl CwIcaControllerCode {
    /// new creates a new [`CwIcaControllerCode`]
    #[must_use]
    pub const fn new(code_id: u64) -> Self {
        Self(code_id)
    }

    /// `code_id` returns the code id of this code
    #[must_use]
    pub const fn code_id(&self) -> u64 {
        self.0
    }

    /// `instantiate` creates a [`WasmMsg::Instantiate`] message targeting this code
    ///
    /// # Errors
    ///
    /// This function returns an error if the given message cannot be serialized
    pub fn instantiate(
        &self,
        msg: impl Into<msg::InstantiateMsg>,
        label: impl Into<String>,
        admin: Option<impl Into<String>>,
    ) -> StdResult<CosmosMsg> {
        let msg = to_json_binary(&msg.into())?;
        Ok(WasmMsg::Instantiate {
            code_id: self.code_id(),
            msg,
            funds: vec![],
            label: label.into(),
            admin: admin.map(Into::into),
        }
        .into())
    }

    /// `instantiate2` returns a [`WasmMsg::Instantiate2`] message targeting this code
    /// and the contract address.
    ///
    /// **Warning**: This function won't work on chains which have substantially changed
    /// address generation such as Injective, test carefully.
    ///
    /// # Errors
    ///
    /// This function returns an error if the given message cannot be serialized or
    /// if the contract address cannot be calculated.
    #[allow(clippy::too_many_arguments)]
    pub fn instantiate2(
        &self,
        api: &dyn Api,
        querier: &QuerierWrapper,
        env: &Env,
        msg: impl Into<msg::InstantiateMsg>,
        label: impl Into<String>,
        admin: Option<impl Into<String>>,
        salt: impl Into<String>,
    ) -> StdResult<(CosmosMsg, Addr)> {
        let salt = salt.into();
        let code_info = querier.query_wasm_code_info(self.code_id())?;
        let creator_cannonical = api.addr_canonicalize(env.contract.address.as_str())?;

        let contract_addr = api.addr_humanize(
            &instantiate2_address(
                code_info.checksum.as_slice(),
                &creator_cannonical,
                salt.as_bytes(),
            )
            .map_err(|e| StdError::generic_err(e.to_string()))?,
        )?;

        let instantiate_msg = WasmMsg::Instantiate2 {
            code_id: self.code_id(),
            msg: to_json_binary(&msg.into())?,
            funds: vec![],
            label: label.into(),
            admin: admin.map(Into::into),
            salt: salt.as_bytes().into(),
        };

        Ok((instantiate_msg.into(), contract_addr))
    }
}

impl<'a> CwIcaControllerContractQuerier<'a> {
    /// Creates a new [`LightClientContractQuerier`]
    #[must_use]
    pub const fn new(querier: &'a QuerierWrapper<'a>, addr: String) -> Self {
        Self { querier, addr }
    }

    /// `get_channel` sends a [`msg::QueryMsg::GetChannel`] query to this contract.
    ///
    /// # Errors
    ///
    /// This function returns an error if the query fails
    pub fn get_channel(&self) -> StdResult<state::ChannelState> {
        self.querier
            .query_wasm_smart(&self.addr, &msg::QueryMsg::GetChannel {})
    }

    /// `get_contract_state` sends a [`msg::QueryMsg::GetContractState`] query to this contract.
    ///
    /// # Errors
    ///
    /// This function returns an error if the query fails
    pub fn get_contract_state(&self) -> StdResult<state::ContractState> {
        self.querier
            .query_wasm_smart(&self.addr, &msg::QueryMsg::GetContractState {})
    }

    /// `ownership` sends a [`msg::QueryMsg::Ownership`] query to this contract.
    ///
    /// # Errors
    /// This function returns an error if the query fails
    pub fn ownership(&self) -> StdResult<cw_ownable::Ownership<String>> {
        self.querier
            .query_wasm_smart(&self.addr, &msg::QueryMsg::Ownership {})
    }
}
