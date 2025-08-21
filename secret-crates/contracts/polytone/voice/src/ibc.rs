#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Addr, CosmosMsg, DepsMut, Empty, Env, IbcBasicResponse,
    IbcChannelCloseMsg, IbcChannelConnectMsg, IbcChannelOpenMsg, IbcChannelOpenResponse,
    IbcPacketAckMsg, IbcPacketReceiveMsg, IbcPacketTimeoutMsg, IbcReceiveResponse, Reply, Response,
    SubMsg, SubMsgResult, WasmMsg,
};

use polytone::{
    ack::{ack_execute_fail, ack_fail},
    callbacks::Callback,
    handshake::voice,
    ibc::Never,
    msgs::voice::{ExecuteMsg, SenderInfo},
    utils::{parse_reply_execute_data, MsgExecuteContractResponse},
};

use crate::{
    error::ContractError,
    state::{CHANNEL_TO_CONNECTION, PENDING_PROXY_TXS, PROXY_TO_SENDER, SENDER_TO_PROXY},
};

const REPLY_ACK: u64 = 0;
pub(crate) const REPLY_FORWARD_DATA: u64 = 1;
pub(crate) const REPLY_INIT_PROXY: u64 = 710;

/// The amount of gas that needs to be reserved for the reply method
/// to return an ACK for a submessage that runs out of gas.
///
/// Use `TestVoiceOutOfGas` in `tests/simtests/functionality_test.go`
/// to tune this. Note that it is best to give this a lot of headroom
/// as gas usage is non-deterministic in the SDK and a limit tuned
/// within 50 gas is liable to fail non-deterministically.
pub(crate) const ACK_GAS_NEEDED: u64 = 101_000;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_channel_open(
    _deps: DepsMut,
    _env: Env,
    msg: IbcChannelOpenMsg,
) -> Result<IbcChannelOpenResponse, ContractError> {
    voice::open(&msg, &["JSON-CosmosMsg"]).map_err(|e| e.into())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_channel_connect(
    deps: DepsMut,
    _env: Env,
    msg: IbcChannelConnectMsg,
) -> Result<IbcBasicResponse, ContractError> {
    voice::connect(&msg, &["JSON-CosmosMsg"])?;
    CHANNEL_TO_CONNECTION.insert(
        deps.storage,
        &msg.channel().endpoint.channel_id,
        &msg.channel().connection_id,
    )?;
    Ok(IbcBasicResponse::new()
        .add_attribute("method", "ibc_channel_connect")
        .add_attribute("channel_id", msg.channel().endpoint.channel_id.as_str())
        .add_attribute("connection_id", msg.channel().connection_id.as_str()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_channel_close(
    deps: DepsMut,
    _env: Env,
    msg: IbcChannelCloseMsg,
) -> Result<IbcBasicResponse, ContractError> {
    CHANNEL_TO_CONNECTION.remove(deps.storage, &msg.channel().endpoint.channel_id)?;
    Ok(IbcBasicResponse::default()
        .add_attribute("method", "ibc_channel_close")
        .add_attribute("connection_id", msg.channel().connection_id.as_str())
        .add_attribute(
            "counterparty_port_id",
            msg.channel().counterparty_endpoint.port_id.clone(),
        ))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_packet_receive(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, Never> {
    let connection_id = CHANNEL_TO_CONNECTION
        .get(deps.storage, &msg.packet.dest.channel_id.clone())
        .expect("handshake sets mapping");

    Ok(IbcReceiveResponse::default()
        .add_attribute("method", "ibc_packet_receive")
        .add_attribute("connection_id", connection_id.as_str())
        .add_attribute("channel_id", msg.packet.dest.channel_id.as_str())
        .add_attribute("counterparty_port", msg.packet.src.port_id.as_str())
        .add_attribute("packet_sequence", msg.packet.sequence.to_string())
        .add_submessage(SubMsg::reply_always(
            WasmMsg::Execute {
                contract_addr: env.contract.address.into_string(),
                msg: to_binary(&ExecuteMsg::Rx {
                    connection_id,
                    counterparty_port: msg.packet.src.port_id.clone(),
                    data: msg.packet.data.clone(),
                })
                .unwrap(),
                funds: vec![],
                code_hash: "".into(),
            },
            REPLY_ACK,
        )))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, _env: Env, msg: Reply) -> Result<Response, ContractError> {
    let response = Response::new();
    let mut err_data = None;
    let mut msgs = vec![];

    match msg.id {
        REPLY_ACK => Ok(match msg.result {
            SubMsgResult::Err(e) => Response::default()
                .add_attribute("ack_error", &e)
                .set_data(ack_fail(e)),
            SubMsgResult::Ok(_) => {
                let data = parse_reply_execute_data(msg.clone())
                    .expect("execution succeeded")
                    .data
                    .expect("reply_forward_data sets data");
                match from_binary::<Callback>(&data) {
                    Ok(_) => Response::default().set_data(data),
                    Err(e) => Response::default()
                        .set_data(ack_fail(format!("unmarshalling callback data: ({e})"))),
                }
            }
        }),
        REPLY_FORWARD_DATA => match msg.result {
            // Executing the requested messages succeeded. Because more
            // than one message can be dispatched (instantiate proxy &
            // execute proxy), CosmWasm will not automatically
            // percolate the data up so we do so ourselves. Because we
            // don't reply on instantiation, the data here is the
            // result of executing messages on the proxy.
            SubMsgResult::Ok(_) => {
                let MsgExecuteContractResponse { data } = parse_reply_execute_data(msg)?;
                let response =
                    Response::default().add_attribute("method", "reply_forward_data_success");
                Ok(match data {
                    Some(data) => response.set_data(data),
                    None => unreachable!("proxy will always set data"),
                })
            }
            SubMsgResult::Err(err) => Ok(Response::default()
                .add_attribute("method", "reply_forward_data_error")
                .set_data(ack_execute_fail(err))),
        },
        // Since Secret Network does not have instantiate2, we must implement a novel method to access:
        //    a. the `sender`` of the ibc packet.
        //    b. the `proxy_address` we expect to have been instantiated.
        //    c. the  `connection_id` & `counterparty_port` of the note <-> voice pair.
        REPLY_INIT_PROXY => {
            match msg.result {
                SubMsgResult::Ok(sub_msg_response) => {
                    let mut msg_sender = String::default();
                    let mut connection_id = &String::default();
                    let mut remote_port = &String::default();
                    let mut proxy_addr = &String::default();

                    for event in &sub_msg_response.events {
                        match event.ty.as_str() {
                            "recv_packet" => {
                                msg_sender = extract_sender(event.attributes[0].value.as_str());
                                for e in event.attributes.iter() {
                                    match e.key.as_str() {
                                        "connection_id" => {
                                            connection_id = &e.value;
                                        }
                                        "packet_src_port" => {
                                            remote_port = &e.value;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            "instantiate" => {
                                proxy_addr = &event
                                    .attributes
                                    .iter()
                                    .find(|a| a.key == "contract_address")
                                    .expect("contract_address attribute not found in wasm event")
                                    .value;
                            }
                            _ => {}
                        }
                    }

                    SENDER_TO_PROXY.insert(
                        deps.storage,
                        &(connection_id.into(), remote_port.into(), msg_sender.clone()),
                        &Addr::unchecked(proxy_addr),
                    )?;

                    PROXY_TO_SENDER.insert(
                        deps.storage,
                        &Addr::unchecked(proxy_addr),
                        &SenderInfo {
                            connection_id: connection_id.into(),
                            remote_port: remote_port.into(),
                            remote_sender: msg_sender.into(),
                        },
                    )?;

                    // load tx to process now that we have the proxy addr
                    let pending: Vec<CosmosMsg> =
                        from_binary(&PENDING_PROXY_TXS.load(deps.storage)?)?;
                    let submsg: SubMsg<Empty> = SubMsg::reply_always(
                        WasmMsg::Execute {
                            contract_addr: proxy_addr.to_string(),
                            msg: to_binary(&polytone::msgs::proxy::ExecuteMsg::Proxy {
                                msgs: pending,
                            })?,
                            funds: vec![],
                            code_hash: "".to_string(),
                        },
                        REPLY_FORWARD_DATA,
                    );

                    msgs.push(submsg)
                }
                SubMsgResult::Err(e) => {
                    err_data = Some(ack_execute_fail(e));
                }
            }

            Ok(match err_data {
                Some(data) => response
                    .add_attribute("method", "reply_forward_data_error")
                    .set_data(data),
                None => response,
            })
        }

        _ => unreachable!("unknown reply ID"),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_packet_ack(
    _deps: DepsMut,
    _env: Env,
    _ack: IbcPacketAckMsg,
) -> Result<IbcBasicResponse, ContractError> {
    unreachable!("host will never send a packet")
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_packet_timeout(
    _deps: DepsMut,
    _env: Env,
    _msg: IbcPacketTimeoutMsg,
) -> Result<IbcBasicResponse, ContractError> {
    unreachable!("host will never send a packet")
}

fn extract_sender(packet_data: &str) -> String {
    let sender_prefix = "\"sender\":\"";
    let start = packet_data
        .find(sender_prefix)
        .expect("She made herself stronger by fighting with the wind.");
    let start = start + sender_prefix.len();
    let end = packet_data[start..]
        .find('"')
        .expect("It is the sun shining on the rain and the rain falling on the sunshine");
    packet_data[start..start + end].to_string()
}
