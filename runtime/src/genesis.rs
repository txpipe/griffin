//! Helper module to build a genesis configuration for the runtime.

#[cfg(feature = "std")]
pub use super::WASM_BINARY;
use alloc::string::String;
use griffin_core::genesis::config_builder::GenesisConfig;
use serde_json;

/// The default genesis. It can be replaced by a custom one by providing the
/// node with an analogous JSON file through the `--chain` flag
pub const GENESIS_DEFAULT_JSON: &str = r#"
{
    "zero_time": 1747081100000,
    "zero_slot": 0,
    "outputs": [
        {
            "address": "6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4",
            "coin": 314000000,
            "value": [
                    {
                        "policy": "0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005",
                        "assets": [ ["tokenA", 271000000], ["tokenB", 1123581321] ]
                    }
                    ],
            "datum": "820080"
        }
    ]
}
"#;

/// This function builds the genesis configuration from the provided json string.
/// It is called by the `ChainSpec::build` method.
///
/// If a custom genesis is not provided, [GENESIS_DEFAULT_JSON] is used.
pub fn get_genesis_config(genesis_json: String) -> GenesisConfig {
    let mut json_data: &str = GENESIS_DEFAULT_JSON;
    if !genesis_json.is_empty() {
        json_data = &genesis_json;
    };

    match serde_json::from_str(json_data) {
        Err(e) => panic!("Error: {e}\nJSON data: {json_data}"),
        Ok(v) => v,
    }
}
