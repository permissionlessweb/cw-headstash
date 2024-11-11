#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, Attribute, Binary, Deps, DepsMut, Env, Event, MessageInfo, Response,
    StdError, StdResult, Storage,
};
use cw2::set_contract_version;
use sha2::{Digest, Sha256};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Glob, GlobHash, GLOBMAP, HASHMAP, OWNER};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:cw-glob";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    // set owners
    for addr in msg.owners.clone() {
        deps.api.addr_validate(&addr)?;
    }
    OWNER.save(deps.storage, &msg.owners)?;

    // hash cw-headstsh & snip120u
    let default_keys = vec!["cw-headstash".to_string(), "snip120u".to_string()];
    let res = perform_hash_glob(deps.storage, default_keys)?;

    Ok(res)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::AddGlob { globs } => add_glob(deps.storage, info.sender, globs),
        ExecuteMsg::TakeGlob {
            sender,
            key,
            memo,
            timeout,
        } => take_glob(
            deps.storage,
            info.sender,
            Addr::unchecked(sender),
            key,
            memo,
            timeout,
        ),
        ExecuteMsg::HashGlob { keys } => perform_hash_glob(deps.storage, keys),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GlobHash { keys } => to_json_binary(&query_glob_hash(deps.storage, keys)?),
    }
}

fn query_glob_hash(storage: &dyn Storage, keys: Vec<String>) -> StdResult<Vec<GlobHash>> {
    let mut hashes = vec![];
    for key in keys {
        let hash = HASHMAP.load(storage, key.clone())?;
        let glob_hash = GlobHash { key, hash };
        hashes.push(glob_hash);
    }
    Ok(hashes)
}

fn perform_hash_glob(
    storage: &mut dyn Storage,
    keys: Vec<String>,
) -> Result<Response, ContractError> {
    let mut attrs = vec![];
    let res = Response::new();
    for key in keys {
        // check if hash already exists
        if !HASHMAP.has(storage, key.clone()) {
            if key == "cw-headstash" || key == "snip120u" {
                let glob = headstash::take_glob(&key.clone())?;
                let hash = hash_glob(Binary::new(glob));
                HASHMAP.save(storage, key.clone(), &hash)?;
                attrs.extend(vec![
                    Attribute::new("glob-key", key.clone()),
                    Attribute::new("glob-hash", hash),
                ])
            } else {
                let glob = GLOBMAP.load(storage, key.clone())?;
                let hash = hash_glob(glob);
                HASHMAP.save(storage, key.clone(), &hash)?;
                attrs.extend(vec![
                    Attribute::new("glob-key", key),
                    Attribute::new("glob-hash", hash),
                ])
            }
        }
    }

    Ok(res.add_attributes(attrs))
}
fn add_glob(
    storage: &mut dyn Storage,
    owner: Addr,
    globs: Vec<Glob>,
) -> Result<Response, ContractError> {
    if !OWNER.load(storage)?.contains(&owner.to_string()) {
        return Err(ContractError::OwnershipError(
            cw_ownable::OwnershipError::NotOwner,
        ));
    }
    let mut attrs = vec![];
    for glob in globs {
        if GLOBMAP.has(storage, glob.key.clone()) {
            return Err(ContractError::KeyExists {
                key: glob.key.clone(),
            });
        } else {
            GLOBMAP.save(storage, glob.key.clone(), &glob.blob)?;
            // generate hash
            let hash = hash_glob(glob.blob);
            HASHMAP.save(storage, glob.key.clone(), &hash)?;

            attrs.extend(vec![
                Attribute::new("glob-key", glob.key),
                Attribute::new("glob-hash", hash),
            ])
        }
    }
    Ok(Response::new().add_attributes(attrs))
}

fn take_glob(
    storage: &mut dyn Storage,
    owner: Addr,
    sender: Addr,
    wasm: String,
    memo: Option<String>,
    timeout: Option<u64>,
) -> Result<Response, ContractError> {
    if !OWNER.load(storage)?.contains(&owner.to_string()) {
        return Err(ContractError::OwnershipError(
            cw_ownable::OwnershipError::NotOwner,
        ));
    }
    let msg = headstash::take_glob(&wasm)?;
    Ok(Response::new().set_data(msg).add_event(
        Event::new("headstash")
            .add_attribute("sender", sender.to_string())
            .add_attribute("memo", memo.unwrap_or_default())
            .add_attribute("timeout", timeout.unwrap_or(600).to_string()),
    ))
}

fn hash_glob(glob: Binary) -> String {
    let mut hasher = Sha256::new();
    hasher.update(glob);
    let hash = hasher.finalize();
    hex::encode(hash)
}

mod headstash {
    use super::*;

    /// Defines the Stargate msg to upload the nested wasm blobs.
    pub fn take_glob(wasm: &str) -> Result<Vec<u8>, StdError> {
        // define headstash wasm binary
        let headstash_bin = match wasm {
            "cw-headstash" => include_bytes!("./globs/cw_headstash.wasm.gz").to_vec(),
            "snip120u" => include_bytes!("./globs/snip120u_impl.wasm.gz").to_vec(),
            _ => return Err(StdError::generic_err("bad contract upload")),
        };

        Ok(headstash_bin)
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{
        from_json,
        testing::{message_info, mock_dependencies, mock_env},
        Binary,
    };
    use cw_ownable::OwnershipError;

    use crate::{
        contract::query,
        msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
        state::{Glob, GlobHash},
        ContractError,
    };

    use super::{execute, instantiate};

    // assure we can grab proper upload msg
    #[test]
    fn test_integration() {
        // simulated testing environment
        let mut deps = mock_dependencies();
        let env = mock_env();

        // simulated addrs
        let creator = deps.api.addr_make("creator");
        let owner = deps.api.addr_make("owner");

        // simulated message info
        let info_owner = message_info(&owner, &[]);
        let info_creator = message_info(&creator, &[]);

        let init_msg = InstantiateMsg {
            owners: vec![owner.to_string()],
        };

        // instantiate
        instantiate(deps.as_mut(), env.clone(), info_creator.clone(), init_msg).unwrap();

        // add first glob
        let add_glob = ExecuteMsg::AddGlob {
            globs: vec![Glob {
                key: "papaya_kush".into(),
                blob: Binary::new(vec![]),
            }],
        };

        // cannot add if not owner
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_creator.clone(),
            add_glob.clone(),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), OwnershipError::NotOwner.to_string());

        let res = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            add_glob.clone(),
        )
        .unwrap();

        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "glob-key")
                .unwrap()
                .value,
            "papaya_kush".to_string()
        );

        // cannot add same key twice
        let err: crate::ContractError =
            execute(deps.as_mut(), env.clone(), info_owner.clone(), add_glob).unwrap_err();
        assert_eq!(
            err.to_string(),
            ContractError::KeyExists {
                key: "papaya_kush".to_string()
            }
            .to_string()
        );

        // grab bytes for snip120u
        let take_glob_snip120u = ExecuteMsg::TakeGlob {
            sender: owner.to_string(),
            key: "snip120u".into(),
            memo: None,
            timeout: None,
        };

        // cannot take glob if not owner
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_creator.clone(),
            take_glob_snip120u.clone(),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), OwnershipError::NotOwner.to_string());

        let res = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            take_glob_snip120u,
        )
        .unwrap();

        // confirm wasm blob is in data on response
        assert!(res.data.is_some());

        let keys = vec![
            "cw-headstash".into(),
            "snip120u".into(),
            "papaya_kush".into(),
        ];

        // set hashes for default
        let set_hash_msg = ExecuteMsg::HashGlob {
            keys: vec!["cw-headstash".into(), "snip120u".into()],
        };

        let res = execute(
            deps.as_mut(),
            env.clone(),
            info_creator.clone(),
            set_hash_msg.clone(),
        )
        .unwrap();
        println!("{:#?}", res);

        // confirm we get queries
        let query_msg = QueryMsg::GlobHash { keys: keys.clone() };
        let res = query(deps.as_ref(), env.clone(), query_msg).unwrap();
        let response: Vec<GlobHash> = from_json(&res).unwrap();

        assert_eq!(response.len(), 3);
        println!("{:#?}", response);
    }

    // query glob hashes

    // track gas_consumption
}
