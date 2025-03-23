#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Addr, Attribute, Binary, ContractResult, Deps, DepsMut, Empty, Env,
    Event, MessageInfo, Response, StdError, StdResult, Storage, SubMsg, SystemResult, Uint64,
    WasmMsg,
};
// use cw2::set_contract_version;

use polytone::ack::{ack_query_fail, ack_query_success};
use polytone::ibc::{Msg, Packet};

use crate::error::ContractError;
use crate::ibc::{ACK_GAS_NEEDED, REPLY_FORWARD_DATA, REPLY_INIT_PROXY};
use crate::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use crate::state::{
    BLOCK_MAX_GAS, CONTRACT_ADDR_LEN, PENDING_PROXY_TXS, PROXY_CODE_ID, PROXY_TO_SENDER,
    SENDER_TO_PROXY,
};

// const CONTRACT_NAME: &str = "crates.io:polytone-voice";
// const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    // set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    if msg.proxy_code_id.is_zero() {
        return Err(ContractError::CodeIdCantBeZero);
    }

    if msg.block_max_gas.u64() <= ACK_GAS_NEEDED {
        return Err(ContractError::GasLimitsMismatch);
    }

    let contract_addr_len = msg.contract_addr_len.unwrap_or(32);
    if contract_addr_len == 0 {
        return Err(ContractError::ContractAddrLenCantBeZero);
    }
    if contract_addr_len > 32 {
        return Err(ContractError::ContractAddrLenCantBeGreaterThan32);
    }

    PROXY_CODE_ID.save(deps.storage, &msg.proxy_code_id.u64())?;
    BLOCK_MAX_GAS.save(deps.storage, &msg.block_max_gas.u64())?;
    CONTRACT_ADDR_LEN.save(deps.storage, &contract_addr_len)?;

    Ok(Response::default()
        .add_attribute("method", "instantiate")
        .add_attribute("proxy_code_id", msg.proxy_code_id)
        .add_attribute("block_max_gas", msg.block_max_gas)
        .add_attribute("contract_addr_len", contract_addr_len.to_string()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Rx {
            connection_id,
            counterparty_port,
            data,
        } => {
            if info.sender != env.contract.address {
                Err(ContractError::NotSelf)
            } else {
                let Packet { sender, msg } = from_binary(&data)?;
                match msg {
                    Msg::Query { msgs } => {
                        let mut results = Vec::with_capacity(msgs.len());
                        for msg in msgs {
                            let query_result = deps.querier.raw_query(&to_binary(&msg)?);
                            let error = match query_result {
                                SystemResult::Ok(ContractResult::Err(error)) => {
                                    format!("contract: {error}")
                                }
                                SystemResult::Err(error) => format!("system: {error}"),
                                SystemResult::Ok(ContractResult::Ok(res)) => {
                                    results.push(res);
                                    continue;
                                }
                            };
                            return Ok(Response::default()
                                .add_attribute("method", "rx_query_fail")
                                .add_attribute("query_index", results.len().to_string())
                                .add_attribute("query_error", error.as_str())
                                .set_data(ack_query_fail(
                                    Uint64::new(results.len() as u64),
                                    error,
                                )));
                        }
                        Ok(Response::default()
                            .add_attribute("method", "rx_query_success")
                            .add_attribute("queries_executed", results.len().to_string())
                            .set_data(ack_query_success(results)))
                    }
                    Msg::Execute { msgs } => {
                        let (instantiate, proxy) = if let Some(proxy) = SENDER_TO_PROXY.get(
                            deps.storage,
                            &(
                                connection_id.clone(),
                                counterparty_port.clone(),
                                sender.clone(),
                            ),
                        ) {
                            (None, proxy)
                        } else {
                            // create proxy, save to state using submessage reply
                            let code_id = PROXY_CODE_ID.load(deps.storage)?;
                            (
                                Some(WasmMsg::Instantiate {
                                    admin: None,
                                    code_id,
                                    label: format!("polytone-proxy {sender}"),
                                    msg: to_binary(&polytone_proxy::msg::InstantiateMsg {})?,
                                    funds: vec![],
                                    code_hash: "".to_string(),
                                }),
                                Addr::unchecked("placeholder"), // set placeholder
                            )
                        };

                        // secret network does not support instantiate2. helper to pass either proxy init msgs, or tx for proxy to handle on reply
                        let submsg = proxy_submessage_helper(
                            deps.storage,
                            &connection_id,
                            &counterparty_port,
                            proxy,
                            &sender,
                            msgs,
                            instantiate,
                        )?;

                        Ok(Response::default()
                            .add_attribute("method", "rx_execute")
                            .add_submessage(submsg.0)
                            .add_event(Event::new("headstash").add_attributes(submsg.1)))
                    }
                }
            }
        }
    }
}

// /// Generates the salt used to generate an address for a user's
// /// account.
// ///
// /// `local_channel` is not attacker controlled and protects from
// /// collision from an attacker generated duplicate
// /// chain. `remote_port` ensures that two different modules on the
// /// same chain produce different addresses for the same
// /// `remote_sender`.
// fn salt(local_connection: &str, counterparty_port: &str, remote_sender: &str) -> Binary {
//     use sha2::{Digest, Sha512};
//     // the salt can be a max of 64 bytes (512 bits).
//     let hash = Sha512::default()
//         .chain_update(local_connection.as_bytes())
//         .chain_update(counterparty_port.as_bytes())
//         .chain_update(remote_sender.as_bytes())
//         .finalize();
//     Binary::from(hash.as_slice())
// }

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::BlockMaxGas => to_binary(&BLOCK_MAX_GAS.load(deps.storage)?),
        QueryMsg::ProxyCodeId => to_binary(&PROXY_CODE_ID.load(deps.storage)?),
        QueryMsg::ContractAddrLen => to_binary(&CONTRACT_ADDR_LEN.load(deps.storage)?),
        QueryMsg::SenderInfoForProxy { proxy } => to_binary(
            &PROXY_TO_SENDER
                .get(deps.storage, &deps.api.addr_validate(&proxy)?)
                .expect("shouldnt panic"),
        ),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, msg: MigrateMsg) -> Result<Response, ContractError> {
    match msg {
        MigrateMsg::WithUpdate {
            proxy_code_id,
            block_max_gas,
            contract_addr_len,
        } => {
            if proxy_code_id.is_zero() {
                return Err(ContractError::CodeIdCantBeZero);
            }

            if block_max_gas.u64() <= ACK_GAS_NEEDED {
                return Err(ContractError::GasLimitsMismatch);
            }

            if contract_addr_len == 0 {
                return Err(ContractError::ContractAddrLenCantBeZero);
            }
            if contract_addr_len > 32 {
                return Err(ContractError::ContractAddrLenCantBeGreaterThan32);
            }

            // update the proxy code ID, block max gas, and contract addr len
            PROXY_CODE_ID.save(deps.storage, &proxy_code_id.u64())?;
            BLOCK_MAX_GAS.save(deps.storage, &block_max_gas.u64())?;
            CONTRACT_ADDR_LEN.save(deps.storage, &contract_addr_len)?;

            Ok(Response::default()
                .add_attribute("method", "migrate_with_update")
                .add_attribute("proxy_code_id", proxy_code_id)
                .add_attribute("block_max_gas", block_max_gas)
                .add_attribute("contract_addr_len", contract_addr_len.to_string()))
        }
    }
}

/// if proxy is placeholder, we pass the proxy instantiate msgs as submessage, allowing us to save proxy addr to contract state.
fn proxy_submessage_helper(
    storage: &mut dyn Storage,
    connection_id: &str,
    counterparty_port: &str,
    proxy: Addr,
    sender: &str,
    msgs: Vec<cosmwasm_std::CosmosMsg>,
    instantate_msg: Option<WasmMsg>,
) -> Result<(SubMsg, Vec<Attribute>), ContractError> {
    let mut attrs = vec![];

    if proxy != Addr::unchecked("placeholder") {
        // pass msgs to proxy normally
        let submsg: SubMsg<Empty> = SubMsg::reply_always(
            WasmMsg::Execute {
                contract_addr: proxy.into_string(),
                msg: to_binary(&polytone_proxy::msg::ExecuteMsg::Proxy { msgs })?,
                funds: vec![],
                code_hash: "".to_string(),
            },
            REPLY_FORWARD_DATA,
        );
        return Ok((submsg, attrs));
    } else if let Some(init_msg) = instantate_msg {
        // pass instantiate msg first, save msgs to pass to proxy once instantiated to state
        let submsg: SubMsg<Empty> = SubMsg::reply_always(init_msg, REPLY_INIT_PROXY);
        attrs.extend(vec![
            Attribute::new("connection-id", connection_id),
            Attribute::new("counterparty-port", counterparty_port),
        ]);
        if msgs.len() != 0 {
            PENDING_PROXY_TXS.save(storage, &to_binary(&msgs)?)?;
        }
        return Ok((submsg, attrs));
    } else {
        return Err(ContractError::Std(StdError::generic_err(
            "proxy has not been instantiated, and no instantiate message passed, panic.",
        )));
    }
}

// #[cfg(test)]
// mod tests {
//     use cosmwasm_std::{CanonicalAddr, HexBinary};

//     fn gen_address(
//         local_connection: &str,
//         counterparty_port: &str,
//         remote_sender: &str,
//     ) -> CanonicalAddr {
//         let checksum =
//             HexBinary::from_hex("13a1fc994cc6d1c81b746ee0c0ff6f90043875e0bf1d9be6b7d779fc978dc2a5")
//                 .unwrap();
//         let creator = CanonicalAddr::from((0..90).map(|_| 9).collect::<Vec<u8>>().as_slice());

//         let salt = salt(local_connection, counterparty_port, remote_sender);
//         assert!(salt.len() <= 64);
//         // instantiate2_address(checksum.as_slice(), &creator, &salt).unwrap()
//     }

//     /// Addresses can be generated, and changing inputs changes
//     /// output.
//     #[test]
//     fn test_address_generation() {
//         let one = gen_address("c1", "c1", "c1");
//         let two = gen_address("c2", "c1", "c1");
//         let three = gen_address("c1", "c2", "c1");
//         let four = gen_address("c1", "c1", "c2");
//         assert!(one != two && two != three && three != four)
//     }
// }
