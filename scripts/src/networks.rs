use cw_orch::environment::{ChainKind, NetworkInfo};
//////////////// SUPPORTED NETWORK CONFIGS ////////////////
/// Add more chains in SUPPORTED_CHAINS to include in account framework instance.
use cw_orch::prelude::*;
/// Cw-orch imports
use reqwest::Url;
use std::net::TcpStream;

pub const SUPPORTED_CHAINS: &[ChainInfo] = &[TERP_MAINNET];
pub const TERP_SUPPORTED_NETWORKS: &[ChainInfo] = &SUPPORTED_CHAINS;

pub const GAS_TO_DEPLOY: u64 = 60_000_000;
pub const CONTRACT_COMPILER: &str = "ghcr.io/scrtlabs/secret-contract-optimizer:1.0.13";

/// A helper function to retrieve a [`ChainInfo`] struct for a given chain-id.
/// supported chains are defined by the `SUPPORTED_CHAINS` variable
pub fn terp_parse_networks(net_id: &str) -> Result<ChainInfo, String> {
    TERP_SUPPORTED_NETWORKS
        .iter()
        .find(|net| net.chain_id == net_id)
        .cloned()
        .ok_or(format!("Network not found: {}", net_id))
}

/// Terp Network: <https://github.com/cosmos/chain-registry/blob/master/terpnetwork/chain.json>
pub const TERP_NETWORK: NetworkInfo = NetworkInfo {
    chain_name: "Terp Network",
    pub_address_prefix: "terp",
    coin_type: 114u32,
};

pub const TERP_MAINNET: ChainInfo = ChainInfo {
    kind: ChainKind::Mainnet,
    chain_id: "morocco-1",
    gas_denom: "ubtsg",
    gas_price: 0.025,
    grpc_urls: &["http://grpc"],
    network_info: TERP_NETWORK,
    lcd_url: None,
    fcd_url: None,
};

pub const TERP_TESTNET: ChainInfo = ChainInfo {
    kind: ChainKind::Testnet,
    chain_id: "90u-4",
    gas_denom: "uthiolx",
    gas_price: 0.025,
    grpc_urls: &["http://terp-testnet-grpc.itrocket.net:443"],
    network_info: TERP_NETWORK,
    lcd_url: None,
    fcd_url: None,
};
pub const TERP_LOCAL: ChainInfo = ChainInfo {
    kind: ChainKind::Local,
    chain_id: "120u-1",
    gas_denom: "uthiolx",
    gas_price: 0.025,
    grpc_urls: &["http://localhost:9391"],
    network_info: TERP_NETWORK,
    lcd_url: None,
    fcd_url: None,
};

/// Secret Network: <https://github.com/cosmos/chain-registry/blob/master/secretnetwork/chain.json>
pub const SECRET_NETWORK: NetworkInfo = NetworkInfo {
    chain_name: "Secret Network",
    pub_address_prefix: "secret",
    coin_type: 529u32,
};
pub const SECRET_MAINNET: ChainInfo = ChainInfo {
    kind: ChainKind::Mainnet,
    chain_id: "secret-1",
    gas_denom: "uscrt",
    gas_price: 0.025,
    grpc_urls: &["http://grpc"],
    network_info: SECRET_NETWORK,
    lcd_url: None,
    fcd_url: None,
};

pub const SECRET_TESTNET: ChainInfo = ChainInfo {
    kind: ChainKind::Testnet,
    chain_id: "pulsar-4",
    gas_denom: "uscrt",
    gas_price: 0.025,
    grpc_urls: &["https://grpc.mainnet.secretsaturn.net"],
    network_info: SECRET_NETWORK,
    lcd_url: None,
    fcd_url: None,
};

pub const SECRET_LOCAL: ChainInfo = ChainInfo {
    kind: ChainKind::Local,
    chain_id: "secretdev-1",
    gas_denom: "uscrt",
    gas_price: 0.025,
    grpc_urls: &["http://localhost:9091"],
    network_info: SECRET_NETWORK,
    lcd_url: None,
    fcd_url: None,
};

pub async fn ping_grpc(url_str: &str) -> anyhow::Result<()> {
    let parsed_url = Url::parse(url_str)?;

    let host = parsed_url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("No host in url"))?;

    let port = parsed_url.port_or_known_default().ok_or_else(|| {
        anyhow::anyhow!(
            "No port in url, and no default for scheme {:?}",
            parsed_url.scheme()
        )
    })?;
    let socket_addr = format!("{}:{}", host, port);

    let _ = TcpStream::connect(socket_addr);
    Ok(())
}
