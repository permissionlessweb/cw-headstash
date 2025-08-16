use cw_orch::{interface, prelude::*};

#[interface(
    cw_glob::msg::InstantiateMsg,
    cw_glob::msg::ExecuteMsg,
    cw_glob::msg::QueryMsg,
    cw_glob::msg::MigrateMsg
)]
pub struct HeadstashGlob<Chain>;

impl<Chain: CwEnv> Uploadable for HeadstashGlob<Chain> {
    fn wrapper() -> <Mock as TxHandler>::ContractSource {
        Box::new(
            ContractWrapper::new(
                cw_glob::contract::execute,
                cw_glob::contract::instantiate,
                cw_glob::contract::query,
            )
            .with_migrate(cw_glob::contract::migrate),
        )
    }
    fn wasm(_chain_info: &ChainInfoOwned) -> WasmPath {
        artifacts_dir_from_workspace!()
            .find_wasm_path("cw_glob")
            .unwrap()
    }
}
