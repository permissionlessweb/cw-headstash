use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    from_json, to_json_binary, Addr, Api, Binary, CosmosMsg, IbcPacketAckMsg, IbcPacketTimeoutMsg,
    StdResult, Storage, SubMsgResponse, Uint64, WasmMsg,
};
use cw_storage_plus::Map;

use crate::{
    ack::unmarshal_ack,
    headstash::HeadstashCallback,
};

/// Executed on the callback receiver upon message completion. When
/// being executed, the message will be tagged with "callback":
///
/// ```json
/// {"callback": {
///       "initiator": ...,
///       "initiator_msg": ...,
///       "result": ...,
/// }}
/// ```
#[cw_serde]
pub struct CallbackMessage {
    /// Initaitor on the note chain.
    pub initiator: Addr,
    /// Message sent by the initaitor. This _must_ be base64 encoded
    /// or execution will fail.
    pub initiator_msg: Binary,
    /// Data from the host chain.
    pub result: Callback,
}

#[cw_serde]
pub enum Callback {
    /// Result of executing the requested query, or an error.
    ///
    /// result[i] corresponds to the i'th query and contains the
    /// base64 encoded query response.
    Query(Result<Vec<Binary>, ErrorResponse>),

    /// Result of executing the requested messages, or an error.
    ///
    /// 14/04/23: if a submessage errors the reply handler can see
    /// `codespace: wasm, code: 5`, but not the actual error. as a
    /// result, we can't return good errors for Execution and this
    /// error string will only tell you the error's codespace. for
    /// example, an out-of-gas error is code 11 and looks like
    /// `codespace: sdk, code: 11`.
    Execute(Result<ExecutionResponse, String>),

    /// An error occured that could not be recovered from. The only
    /// known way that this can occur is message handling running out
    /// of gas, in which case the error will be `codespace: sdk, code:
    /// 11`.
    ///
    /// This error is not named becuase it could also occur due to a
    /// panic or unhandled error during message processing. We don't
    /// expect this to happen and have carefully written the code to
    /// avoid it.
    FatalError(String),
}

#[cw_serde]
pub struct ExecutionResponse {
    /// The address on the remote chain that executed the messages.
    pub executed_by: String,
    /// Index `i` corresponds to the result of executing the `i`th
    /// message.
    pub result: Vec<SubMsgResponse>,
}

#[cw_serde]
pub struct ErrorResponse {
    /// The index of the first message who's execution failed.
    pub message_index: Uint64,
    /// The error that occured executing the message.
    pub error: String,
}

/// A request for a callback.
#[cw_serde]
pub struct CallbackRequest {
    pub receiver: String,
    pub msg: Binary,
    /// unique identifier for effecient idenification of headstash callback msg
    pub headstash_digits: u32,
}

/// Disembiguates between a callback for remote message execution and
/// queries.
#[cw_serde]
pub enum CallbackRequestType {
    Execute,
    Query,
}

/// Requests that a callback be returned for the IBC message
/// identified by `(channel_id, sequence_number)`.
pub fn request_callback(
    storage: &mut dyn Storage,
    api: &dyn Api,
    channel_id: String,
    sequence_number: u64,
    initiator: Addr,
    request: Option<CallbackRequest>,
    request_type: CallbackRequestType,
) -> StdResult<()> {
    if let Some(request) = request {
        let receiver = api.addr_validate(&request.receiver)?;
        let initiator_msg = request.msg;
        let key = (channel_id, sequence_number);
        let headstash_callback_id = request.headstash_digits;

        CALLBACKS.save(
            storage,
            key,
            &PendingCallback {
                initiator,
                initiator_msg,
                receiver,
                request_type,
                headstash_callback_id,
            },
        )?;
    }

    Ok(())
}

/// Call on every packet ACK. Returns a callback message to execute,
/// if any, and the address that executed the request on the remote
/// chain (the message initiator's remote account), if any.
///
/// (storage, ack) -> (callback, executed_by)
pub fn on_ack(
    storage: &mut dyn Storage,
    IbcPacketAckMsg {
        acknowledgement,
        original_packet,
        ..
    }: &IbcPacketAckMsg,
) -> (Option<CosmosMsg>, Option<String>) {
    let result = unmarshal_ack(acknowledgement);

    let executed_by = match result {
        Callback::Execute(Ok(ExecutionResponse {
            ref executed_by, ..
        })) => Some(executed_by.clone()),
        _ => None,
    };

    let callback_message = dequeue_callback(
        storage,
        original_packet.src.channel_id.clone(),
        original_packet.sequence,
    )
    .map(|request| callback_message(request, result));

    (callback_message, executed_by)
}

/// Call on every packet timeout. Returns a callback message to execute,
/// if any.
pub fn on_timeout(
    storage: &mut dyn Storage,
    IbcPacketTimeoutMsg { packet, .. }: &IbcPacketTimeoutMsg,
) -> Option<CosmosMsg> {
    let request = dequeue_callback(storage, packet.src.channel_id.clone(), packet.sequence)?;
    let timeout = "timeout".to_string();
    let result = match request.request_type {
        CallbackRequestType::Execute => Callback::Execute(Err(timeout)),
        CallbackRequestType::Query => Callback::Query(Err(ErrorResponse {
            message_index: Uint64::zero(),
            error: timeout,
        })),
    };
    Some(callback_message(request, result))
}

// TODO: implement generic callback request structure,
fn callback_message(request: PendingCallback, result: Callback) -> CosmosMsg {
    /// Gives the executed message a "callback" tag:
    /// `{ "callback": CallbackMsg }`.
    #[cw_serde]
    enum C {
        Callback(CallbackMessage),
        HeadstashCallback(HeadstashCallback),
    }
    let msg =
        match &result {
            Callback::Execute(ref execute_res) => {
                let cb_res = execute_res
                    .clone()
                    .expect("unable to map callback, fatal error");

                match &request.headstash_callback_id {
                    // HeadstashCallback::UploadHeadstashOnSecret: find code id, call note to set code-id to state.
                    101 => {
                        //
                        let code_id = &cb_res.result[0]
                            .events
                            .iter()
                            .find(|e| e.ty == "wasm")
                            .expect("wasm contract uploaded, event expected")
                            .attributes
                            .iter()
                            .find(|a| a.key == "code_id")
                            .expect("wasm contract uploaded, code_id attr expected")
                            .value;

                        to_json_binary(&C::HeadstashCallback(
                            HeadstashCallback::UploadedHeadstashCodeId {
                                code_id: u64::from_str_radix(code_id, 10u32)
                                    .expect("failed from_str_radix"),
                            },
                        ))
                    }
                    202 => {
                        let mut snip20_addrs = Vec::new();
                        // only one smart contract is expected to be instantiated at a time?
                        for res in &cb_res.result {
                            snip20_addrs.push(res
                            .events
                            .iter()
                            .find(|e| e.ty == "wasm")
                            .expect("wasm contract instantiated, event expected")
                            .attributes
                            .iter()
                            .find(|a| a.key == "contract_address")
                            .expect("wasm contract instantiated, contract_address attr expected")
                            .value.clone());
                        }

                        to_json_binary(&C::HeadstashCallback(
                            HeadstashCallback::CreatedSnip20ContractAddr {
                                addr: snip20_addrs[0].clone(),
                            },
                        ))
                    }
                    303 => {
                        //
                        let headstash_addr = &cb_res.result[0]
                            .events
                            .iter()
                            .find(|e| e.ty == "wasm")
                            .expect("wasm contract instantiated, event expected")
                            .attributes
                            .iter()
                            .find(|a| a.key == "contract_address")
                            .expect("wasm contract instantiated, contract_address attr expected")
                            .value;

                        to_json_binary(&C::HeadstashCallback(
                            HeadstashCallback::CreatedHeadstashContractAddr {
                                addr: headstash_addr.into(),
                            },
                        ))
                    }
                    404 => {
                        let headstash_addr = &cb_res.result[0]
                            .events
                            .iter()
                            .find(|e| e.ty == "wasm")
                            .expect("wasm contract instantiated, event expected")
                            .attributes
                            .iter()
                            .find(|a| a.key == "contract_address")
                            .expect("wasm contract instantiated, contract_address attr expected")
                            .value;

                        to_json_binary(&C::HeadstashCallback(
                            HeadstashCallback::CreatedHeadstashContractAddr {
                                addr: headstash_addr.into(),
                            },
                        ))
                    }
                    // fallback to default callback if not headstash msg.
                    _ => to_json_binary(&C::Callback(CallbackMessage {
                        initiator: request.initiator,
                        initiator_msg: request.initiator_msg,
                        result,
                    })),
                }
            }
            _ => to_json_binary(&C::Callback(CallbackMessage {
                initiator: request.initiator,
                initiator_msg: request.initiator_msg,
                result,
            })),
        }
        .expect("fields are known to be serializable");

    WasmMsg::Execute {
        contract_addr: request.receiver.into_string(),
        msg,
        funds: vec![],
    }
    .into()
}

fn dequeue_callback(
    storage: &mut dyn Storage,
    channel_id: String,
    sequence_number: u64,
) -> Option<PendingCallback> {
    let request = CALLBACKS
        .may_load(storage, (channel_id.clone(), sequence_number))
        .unwrap()?;
    CALLBACKS.remove(storage, (channel_id, sequence_number));
    Some(request)
}

#[cw_serde]
struct PendingCallback {
    initiator: Addr,
    initiator_msg: Binary,
    /// The address that will receive the callback on completion.
    receiver: Addr,
    /// Used to return the appropriate callback type during timeouts.
    request_type: CallbackRequestType,
    headstash_callback_id: u32,
}

/// (channel_id, sequence_number) -> callback
const CALLBACKS: Map<(String, u64), PendingCallback> = Map::new("polytone-callbacks");

// default template for normal (non-headstash) callbacks
impl CallbackRequest {
    pub fn callback_template(receiver: String, callback_message: CallbackMessage) -> Self {
        Self {
            receiver,
            msg: to_json_binary(&callback_message).unwrap(),
            headstash_digits: 000,
        }
    }
    pub fn callback_msg_from_template(&self) -> CallbackMessage {
        from_json(&self.msg).expect("expect-to-deserialize")
    }
}
