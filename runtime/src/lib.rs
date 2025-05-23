//! The runtime contains the core logic of the ledger run by the Griffin node.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

extern crate alloc;

pub mod genesis;

use alloc::{string::ToString, vec, vec::Vec};
use codec::{Decode, Encode};
use griffin_core::genesis::config_builder::GenesisConfig;
use griffin_core::MILLI_SECS_PER_SLOT;
use scale_info::TypeInfo;
use sp_api::impl_runtime_apis;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::OpaqueMetadata;
use sp_inherents::InherentData;
use sp_runtime::{
    create_runtime_str, impl_opaque_keys,
    traits::Block as BlockT,
    transaction_validity::{TransactionSource, TransactionValidity},
    ApplyExtrinsicResult, BoundToRuntimeAppPublic,
};

#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
    use super::*;

    // This part is necessary for generating session keys in the runtime
    impl_opaque_keys! {
        pub struct SessionKeys {
            pub aura: AuraAppPublic,
            pub grandpa: GrandpaAppPublic,
        }
    }

    // Typically these are not implemented manually, but rather for the pallet associated with the
    // keys. Here we are not using the pallets, and these implementations are trivial, so we just
    // re-write them.
    pub struct AuraAppPublic;
    impl BoundToRuntimeAppPublic for AuraAppPublic {
        type Public = AuraId;
    }

    pub struct GrandpaAppPublic;
    impl BoundToRuntimeAppPublic for GrandpaAppPublic {
        type Public = sp_consensus_grandpa::AuthorityId;
    }
}

/// This runtime version.
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("griffin-solochain-runtime"),
    impl_name: create_runtime_str!("griffin-solochain-runtime"),
    authoring_version: 1,
    spec_version: 100,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 1,
    state_version: 1,
};

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

pub type Transaction = griffin_core::types::Transaction;
pub type Block = griffin_core::types::Block;
pub type Executive = griffin_core::Executive;
pub type Output = griffin_core::types::Output;

/// The main struct in this module.
#[derive(Encode, Decode, PartialEq, Eq, Clone, TypeInfo)]
pub struct Runtime;

// Here we hard-code consensus authority IDs for the well-known identities that work with the CLI flags
// Such as `--alice`, `--bob`, etc. Only Alice is enabled by default which makes things work nicely
// in a `--dev` node. You may enable more authorities to test more interesting networks, or replace
// these IDs entirely.
impl Runtime {
    /// Aura authority IDs
    fn aura_authorities() -> Vec<AuraId> {
        use hex_literal::hex;
        use sp_application_crypto::ByteArray;

        [
            // Alice
            hex!("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"),
            // Bob
            // hex!("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"),
            // Charlie
            // hex!("90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22"),
            // Dave
            // hex!("306721211d5404bd9da88e0204360a1a9ab8b87c66c1bc2fcdd37f3c2222cc20"),
            // Eve
            // hex!("e659a7a1628cdd93febc04a4e0646ea20e9f5f0ce097d9a05290d4a9e054df4e"),
            // Ferdie
            // hex!("1cbd2d43530a44705ad088af313e18f80b53ef16b36177cd4b77b846f2a5f07c"),
        ]
        .iter()
        .map(|hex| AuraId::from_slice(hex.as_ref()).expect("Valid Aura authority hex was provided"))
        .collect()
    }

    ///Grandpa Authority IDs - All equally weighted
    fn grandpa_authorities() -> sp_consensus_grandpa::AuthorityList {
        use hex_literal::hex;
        use sp_application_crypto::ByteArray;

        [
            // Alice
            hex!("88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee"),
            // Bob
            // hex!("d17c2d7823ebf260fd138f2d7e27d114c0145d968b5ff5006125f2414fadae69"),
            // Charlie
            // hex!("439660b36c6c03afafca027b910b4fecf99801834c62a5e6006f27d978de234f"),
            // Dave
            // hex!("5e639b43e0052c47447dac87d6fd2b6ec50bdd4d0f614e4299c665249bbd09d9"),
            // Eve
            // hex!("1dfe3e22cc0d45c70779c1095f7489a8ef3cf52d62fbd8c2fa38c9f1723502b5"),
            // Ferdie
            // hex!("568cb4a574c6d178feb39c27dfc8b3f789e5f5423e19c71633c748b9acf086b5"),
        ]
        .iter()
        .map(|hex| {
            (
                GrandpaId::from_slice(hex.as_ref())
                    .expect("Valid Grandpa authority hex was provided"),
                1,
            )
        })
        .collect()
    }
}

impl_runtime_apis! {
    // https://substrate.dev/rustdocs/master/sp_api/trait.Core.html
    impl sp_api::Core<Block> for Runtime {
        fn version() -> RuntimeVersion {
            VERSION
        }

        fn execute_block(block: Block) {
            Executive::execute_block(block)
        }

        fn initialize_block(header: &<Block as BlockT>::Header) -> sp_runtime::ExtrinsicInclusionMode {
            Executive::open_block(header)
        }
    }

    // https://substrate.dev/rustdocs/master/sc_block_builder/trait.BlockBuilderApi.html
    impl sp_block_builder::BlockBuilder<Block> for Runtime {
        fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
            Executive::apply_extrinsic(extrinsic)
        }

        fn finalize_block() -> <Block as BlockT>::Header {
            Executive::close_block()
        }

        fn inherent_extrinsics(_data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
            Vec::new()
        }

        fn check_inherents(
            _block: Block,
            _data: InherentData
        ) -> sp_inherents::CheckInherentsResult {
            sp_inherents::CheckInherentsResult::new()
        }
    }

    impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
        fn validate_transaction(
            source: TransactionSource,
            tx: <Block as BlockT>::Extrinsic,
            block_hash: <Block as BlockT>::Hash,
        ) -> TransactionValidity {
            Executive::validate_transaction(source, tx, block_hash)
        }
    }

    impl sp_api::Metadata<Block> for Runtime {
        fn metadata() -> OpaqueMetadata {
            OpaqueMetadata::new(Vec::new())
        }

        fn metadata_at_version(_version: u32) -> Option<OpaqueMetadata> {
            None
        }

        fn metadata_versions() -> alloc::vec::Vec<u32> {
            Default::default()
        }
    }

    impl sp_session::SessionKeys<Block> for Runtime {
        fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
            opaque::SessionKeys::generate(seed)
        }

        fn decode_session_keys(
            encoded: Vec<u8>,
        ) -> Option<Vec<(Vec<u8>, sp_core::crypto::KeyTypeId)>> {
            opaque::SessionKeys::decode_into_raw_public_keys(&encoded)
        }
    }

    impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
        fn slot_duration() -> sp_consensus_aura::SlotDuration {
            sp_consensus_aura::SlotDuration::from_millis(MILLI_SECS_PER_SLOT.into())
        }

        fn authorities() -> Vec<AuraId> {
            Self::aura_authorities()
        }
    }

    impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
        fn grandpa_authorities() -> sp_consensus_grandpa::AuthorityList {
            Self::grandpa_authorities()
        }

        fn current_set_id() -> sp_consensus_grandpa::SetId {
            0u64
        }

        fn submit_report_equivocation_unsigned_extrinsic(
            _equivocation_proof: sp_consensus_grandpa::EquivocationProof<
                <Block as BlockT>::Hash,
                sp_runtime::traits::NumberFor<Block>,
            >,
            _key_owner_proof: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
        ) -> Option<()> {
            None
        }

        fn generate_key_ownership_proof(
            _set_id: sp_consensus_grandpa::SetId,
            _authority_id: sp_consensus_grandpa::AuthorityId,
        ) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
            None
        }
    }

    impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
        fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
            let genesis_config = serde_json::from_slice::<GenesisConfig>(config.as_slice())
                .map_err(|_| "The input JSON is not a valid genesis configuration.")?;

            griffin_core::genesis::GriffinGenesisConfigBuilder::build(genesis_config)
        }

        fn get_preset(_id: &Option<sp_genesis_builder::PresetId>) -> Option<Vec<u8>> {
            let genesis_config : &GenesisConfig = &genesis::get_genesis_config("".to_string());
            Some(serde_json::to_vec(genesis_config)
                 .expect("Genesis configuration is valid."))
        }

        fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
            vec![]
        }
    }
}
