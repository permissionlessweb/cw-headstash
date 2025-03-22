use std::fs;

use cw_headstash::state::{Headstash, Snip};
use serde_json::Value;

/// retrives the list of eligible pubkey and their headstash allocations
pub fn get_addrs_from_json() {
    let data = fs::read_to_string("../data/distribution.json")
        .expect("Something went wrong reading the file");

    let json_value: Vec<Value> = serde_json::from_str(&data).unwrap();

    let mut addrs: Vec<Headstash> = vec![];

    for value in json_value {
        let address = value["pubkey"].as_str().unwrap().to_string();
        let headstashes = value["headstash"].as_array().unwrap();
        let mut headstash_vec: Vec<Snip> = vec![];

        for headstash in headstashes {
            let addr = headstash["addr"].as_str().unwrap().to_string();
            let amount = headstash["amount"].as_u64().unwrap();

            headstash_vec.push(Snip {
                addr,
                amount: amount.into(),
            });
        }

        addrs.push(Headstash {
            addr: address.to_string(),
            snips: vec![Snip],
        });
        addrs.push(Headstash {
            addr: todo!(),
            snips: todo!(),
        });
    }
}
