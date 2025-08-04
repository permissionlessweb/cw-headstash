use cosmwasm_std::{Binary, Uint128};

#[cosmwasm_schema::cw_serde]
pub struct InitialBalance {
    pub address: String,
    pub amount: Uint128,
}

#[cosmwasm_schema::cw_serde]
pub struct InstantiateMsg {
    pub name: String,
    pub admin: Option<String>,
    pub symbol: String,
    pub decimals: u8,
    pub initial_balances: Option<Vec<InitialBalance>>,
    pub prng_seed: Binary,
    pub config: Option<InitConfig>,
    pub supported_denoms: Option<Vec<String>>,
}

#[cosmwasm_schema::cw_serde]
pub struct InitConfig {
    /// Indicates whether the total supply is public or should be kept secret.
    /// default: False
    public_total_supply: Option<bool>,
    /// Indicates whether deposit functionality should be enabled
    /// default: False
    enable_deposit: Option<bool>,
    /// Indicates whether redeem functionality should be enabled
    /// default: False
    enable_redeem: Option<bool>,
    /// Indicates whether mint functionality should be enabled
    /// default: False
    enable_mint: Option<bool>,
    /// Indicates whether burn functionality should be enabled
    /// default: False
    enable_burn: Option<bool>,
    /// Indicated whether an admin can modify supported denoms
    /// default: False
    can_modify_denoms: Option<bool>,
}

#[cosmwasm_schema::cw_serde]
pub struct AddMintersMsg {
    pub minters: Vec<String>,
    pub padding: Option<String>,
}
