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
    gas_denom: "ubtsg",
    gas_price: 0.025,
    grpc_urls: &["http://"],
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
    chain_id: "",
    gas_denom: "uscrt",
    gas_price: 0.025,
    grpc_urls: &["http://"],
    network_info: TERP_NETWORK,
    lcd_url: None,
    fcd_url: None,
};

// Localnet: <https://github.com/cosmos/chain-registry/blob/master/bitsong/chain.json>
const LOCAL_NET: NetworkInfo = NetworkInfo {
    chain_name: "Local Network",
    pub_address_prefix: "mock",
    coin_type: 114u32,
};
pub const LOCAL_NETWORK1: ChainInfo = ChainInfo {
    kind: ChainKind::Testnet,
    chain_id: "local-1",
    gas_denom: "ueret",
    gas_price: 0.025,
    grpc_urls: &["tcp://localhost:9090"],
    network_info: TERP_NETWORK,
    lcd_url: None,
    fcd_url: None,
};
pub const LOCAL_NETWORK2: ChainInfo = ChainInfo {
    kind: ChainKind::Testnet,
    chain_id: "local-2",
    gas_denom: "uskeret",
    gas_price: 0.025,
    grpc_urls: &["http://grpc"],
    network_info: LOCAL_NET,
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
