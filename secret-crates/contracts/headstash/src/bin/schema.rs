use std::env::current_dir;
use std::fs::create_dir_all;

use cosmwasm_schema::write_api;

use cw_headstash::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryAnswer, QueryMsg, SudoMsg};
use cw_headstash::state::Config;

fn main() {
    let mut out_dir = current_dir().unwrap();

    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
        migrate: MigrateMsg,
        sudo: SudoMsg,
    }
 
}