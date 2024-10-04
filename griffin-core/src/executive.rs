//! # Executive Module
//!
//! The executive is the main orchestrator for the entire runtime.
//! It has functions that implement the Core, BlockBuilder, and TxPool runtime APIs.
//!
//! It does all the reusable verification of UTXO transactions.

use crate::{
    ensure,
    types::{Block, BlockNumber, DispatchResult, Header, Input, Transaction, UtxoError},
    utxo_set::TransparentUtxoSet,
    EXTRINSIC_KEY,
    HEADER_KEY,
    HEIGHT_KEY,
    LOG_TARGET,
};
use log::debug;
use parity_scale_codec::{Decode, Encode};
use sp_runtime::{
    traits::{BlakeTwo256, Block as BlockT, Extrinsic, Hash as HashT, Header as HeaderT},
    transaction_validity::{
        TransactionLongevity, TransactionSource, TransactionValidity,
        TransactionValidityError, ValidTransaction,
    },
    ApplyExtrinsicResult, ExtrinsicInclusionMode, StateVersion,
};
use alloc::{collections::btree_set::BTreeSet, vec::Vec};
use alloc::string::String;
use alloc::borrow::Cow;
use alloc::boxed::Box;
use core::iter::zip;
use alloc::vec;

use pallas_applying::{
    validate, UTxOs,
    utils::{
        Environment, MultiEraProtocolParameters, BabbageProtParams
    },
};
use pallas_primitives::babbage::{
    MintedTx, Value, MintedDatumOption, MintedScriptRef,
    PseudoTransactionOutput, MintedPostAlonzoTransactionOutput,
    MintedTransactionOutput, MintedTransactionBody,
    ExUnits, ExUnitPrices, CostMdls, RationalNumber,
    Nonce, NonceVariant,
};
use pallas_traverse::{MultiEraTx, MultiEraInput, MultiEraOutput};
use pallas_codec::utils::{CborWrap, Bytes};

/// The executive. Each runtime is encouraged to make a type alias called `Executive` that fills
/// in the proper generic types.
pub struct Executive;

pub fn babbage_minted_tx_from_cbor(tx_cbor: &[u8]) -> MintedTx<'_> {
    pallas_codec::minicbor::decode::<MintedTx>(&tx_cbor[..]).unwrap()
}

pub fn mk_utxo_for_babbage_tx<'a>(
    tx_body: &MintedTransactionBody,
    tx_outs_info: &'a [(
        String, // address in string format
        Value,
        Option<MintedDatumOption>,
        Option<CborWrap<MintedScriptRef>>,
    )],
) -> UTxOs<'a> {
    let mut utxos: UTxOs = UTxOs::new();
    for (tx_in, (addr, val, datum_opt, script_ref)) in zip(tx_body.inputs.clone(), tx_outs_info) {
        let multi_era_in: MultiEraInput =
            MultiEraInput::AlonzoCompatible(Box::new(Cow::Owned(tx_in)));
        let address_bytes: Bytes = match hex::decode(addr) {
            Ok(bytes_vec) => Bytes::from(bytes_vec),
            _ => panic!("Unable to decode input address"),
        };
        let tx_out: MintedTransactionOutput =
            PseudoTransactionOutput::PostAlonzo(MintedPostAlonzoTransactionOutput {
                address: address_bytes,
                value: val.clone(),
                datum_option: datum_opt.clone(),
                script_ref: script_ref.clone(),
            });
        let multi_era_out: MultiEraOutput = MultiEraOutput::Babbage(Box::new(Cow::Owned(tx_out)));
        utxos.insert(multi_era_in, multi_era_out);
    }
    utxos
}

fn mk_mainnet_params_epoch_365() -> BabbageProtParams {
    BabbageProtParams {
        minfee_a: 44,
        minfee_b: 155381,
        max_block_body_size: 90112,
        max_transaction_size: 16384,
        max_block_header_size: 1100,
        key_deposit: 2000000,
        pool_deposit: 500000000,
        maximum_epoch: 18,
        desired_number_of_stake_pools: 500,
        pool_pledge_influence: RationalNumber {
            numerator: 3,
            denominator: 10,
        },
        expansion_rate: RationalNumber {
            numerator: 3,
            denominator: 1000,
        },
        treasury_growth_rate: RationalNumber {
            numerator: 2,
            denominator: 10,
        },
        decentralization_constant: RationalNumber {
            numerator: 0,
            denominator: 1,
        },
        extra_entropy: Nonce {
            variant: NonceVariant::NeutralNonce,
            hash: None,
        },
        protocol_version: (7, 0),
        min_pool_cost: 340000000,
        ada_per_utxo_byte: 4310,
        cost_models_for_script_languages: CostMdls {
            plutus_v1: Some(vec![
                197209, 0, 1, 1, 396231, 621, 0, 1, 150000, 1000, 0, 1, 150000, 32, 2477736,
                29175, 4, 29773, 100, 29773, 100, 29773, 100, 29773, 100, 29773, 100, 29773,
                100, 100, 100, 29773, 100, 150000, 32, 150000, 32, 150000, 32, 150000, 1000, 0,
                1, 150000, 32, 150000, 1000, 0, 8, 148000, 425507, 118, 0, 1, 1, 150000, 1000,
                0, 8, 150000, 112536, 247, 1, 150000, 10000, 1, 136542, 1326, 1, 1000, 150000,
                1000, 1, 150000, 32, 150000, 32, 150000, 32, 1, 1, 150000, 1, 150000, 4,
                103599, 248, 1, 103599, 248, 1, 145276, 1366, 1, 179690, 497, 1, 150000, 32,
                150000, 32, 150000, 32, 150000, 32, 150000, 32, 150000, 32, 148000, 425507,
                118, 0, 1, 1, 61516, 11218, 0, 1, 150000, 32, 148000, 425507, 118, 0, 1, 1,
                148000, 425507, 118, 0, 1, 1, 2477736, 29175, 4, 0, 82363, 4, 150000, 5000, 0,
                1, 150000, 32, 197209, 0, 1, 1, 150000, 32, 150000, 32, 150000, 32, 150000, 32,
                150000, 32, 150000, 32, 150000, 32, 3345831, 1, 1,
            ]),

            plutus_v2: None,
        },
        execution_costs: ExUnitPrices {
            mem_price: RationalNumber {
                numerator: 577,
                denominator: 10000,
            },
            step_price: RationalNumber {
                numerator: 721,
                denominator: 10000000,
            },
        },
        max_tx_ex_units: ExUnits {
            mem: 14000000,
            steps: 10000000000,
        },
        max_block_ex_units: ExUnits {
            mem: 62000000,
            steps: 40000000000,
        },
        max_value_size: 5000,
        collateral_percentage: 150,
        max_collateral_inputs: 3,
    }
}

impl Executive
where
    Block: BlockT,
    Transaction: Extrinsic,
{
    /// Does pool-style validation of a griffin transaction.
    /// Does not commit anything to storage.
    /// This returns Ok even if some inputs are still missing because the tagged transaction pool can handle that.
    /// We later check that there are no missing inputs in `apply_griffin_transaction`
    pub fn validate_griffin_transaction(
        transaction: &Transaction,
    ) -> Result<ValidTransaction, UtxoError> {
        debug!(
            target: LOG_TARGET,
            "validating griffin transaction",
        );

        let cbor_bytes: Vec<u8> = hex::decode(include_str!("../babbage3.tx")).unwrap();
        let mtx: MintedTx = babbage_minted_tx_from_cbor(&cbor_bytes);
        let metx: MultiEraTx = MultiEraTx::from_babbage(&mtx);
        let tx_outs_info: &[(
            String,
            Value,
            Option<MintedDatumOption>,
            Option<CborWrap<MintedScriptRef>>,
        )] = &[(
            String::from("011be1f490912af2fc39f8e3637a2bade2ecbebefe63e8bfef10989cd6f593309a155b0ebb45ff830747e61f98e5b77feaf7529ce9df351382"),
            Value::Coin(103324335),
            None,
            None,
        )];
        let utxos: UTxOs = mk_utxo_for_babbage_tx(&mtx.transaction_body, tx_outs_info);
        let env: Environment = Environment {
            prot_params: MultiEraProtocolParameters::Babbage(mk_mainnet_params_epoch_365()),
            prot_magic: 764824073,
            block_slot: 72316896,
            network_id: 1,
        };
        match validate(&metx, &utxos, &env) {
            Ok(()) => (),
            Err(err) => assert!(false, "Unexpected error ({:?})", err),
        }

        // There must be at least one input
        ensure!(!transaction.transaction_body.inputs.is_empty(), UtxoError::NoInputs);

        // Make sure there are no duplicate inputs
        {
            let input_set: BTreeSet<_> = transaction.transaction_body.inputs.iter().map(|o| o.encode()).collect();
            ensure!(
                input_set.len() == transaction.transaction_body.inputs.len(),
                UtxoError::DuplicateInput
            );
        }

        // Keep track of any missing inputs for use in the tagged transaction pool
        let mut missing_inputs = Vec::new();
        for input in transaction.transaction_body.inputs.iter() {
            if None == TransparentUtxoSet::peek_utxo(&input) {
                missing_inputs.push(input.clone().encode());
            }
        }

        // Make sure no outputs already exist in storage
        let tx_hash = BlakeTwo256::hash_of(&transaction.encode());
        for index in 0..transaction.transaction_body.outputs.len() {
            let input = Input {
                tx_hash,
                index: index as u32,
            };

            debug!(
                target: LOG_TARGET,
                "Checking for pre-existing output {:?}", input
            );

            ensure!(
                TransparentUtxoSet::peek_utxo(&input).is_none(),
                UtxoError::PreExistingOutput
            );
        }

        // Calculate the tx-pool tags provided by this transaction, which
        // are just the encoded Inputs
        let provides = (0..transaction.transaction_body.outputs.len())
            .map(|i| {
                let input = Input {
                    tx_hash,
                    index: i as u32,
                };
                input.encode()
            })
            .collect::<Vec<_>>();

        // If any of the inputs are missing, we cannot make any more progress
        if !missing_inputs.is_empty() {
            debug!(
                target: LOG_TARGET,
                "Transaction is valid but still has missing inputs. Returning early.",
            );
            return Ok(ValidTransaction {
                requires: missing_inputs,
                provides,
                priority: 0,
                longevity: TransactionLongevity::MAX,
                propagate: true,
            });
        }

        // Return the valid transaction
        Ok(ValidTransaction {
            requires: Vec::new(),
            provides,
            priority: 0,
            longevity: TransactionLongevity::MAX,
            propagate: true,
        })
    }

    /// Does full verification and application of griffin transactions.
    /// Most of the validation happens in the call to `validate_griffin_transaction`.
    /// Once those checks are done we make sure there are no missing inputs and then update storage.
    pub fn apply_griffin_transaction(transaction: Transaction) -> DispatchResult {
        debug!(
            target: LOG_TARGET,
            "applying griffin transaction {:?}", transaction
        );

        // Re-do the pre-checks. These should have been done in the pool, but we can't
        // guarantee that foreign nodes do these checks faithfully, so we need to check on-chain.
        let valid_transaction = Self::validate_griffin_transaction(&transaction)?;

        // If there are still missing inputs, we cannot execute this,
        // although it would be valid in the pool
        ensure!(
            valid_transaction.requires.is_empty(),
            UtxoError::MissingInput
        );

        // At this point, all validation is complete, so we can commit the storage changes.
        Self::update_storage(transaction);

        Ok(())
    }

    /// Helper function to update the utxo set according to the given transaction.
    /// This function does absolutely no validation. It assumes that the transaction
    /// has already passed validation. Changes proposed by the transaction are written
    /// blindly to storage.
    fn update_storage(transaction: Transaction) {
        // Remove verified UTXOs
        for input in &transaction.transaction_body.inputs {
            TransparentUtxoSet::consume_utxo(&input);
        }

        debug!(
            target: LOG_TARGET,
            "Transaction before updating storage {:?}", transaction
        );
        // Write the newly created utxos
        for (index, output) in transaction.transaction_body.outputs.iter().enumerate() {
            let input = Input {
                tx_hash: BlakeTwo256::hash_of(&transaction.encode()),
                index: index as u32,
            };
            TransparentUtxoSet::store_utxo(input, output);
        }
    }

    /// A helper function that allows griffin runtimes to read the current block height
    pub fn block_height() -> BlockNumber {
        sp_io::storage::get(HEIGHT_KEY)
            .and_then(|d| BlockNumber::decode(&mut &*d).ok())
            .expect("A height is stored at the beginning of block one and never cleared.")
    }

    // These next three methods are for the block authoring workflow.
    // Open the block, apply zero or more extrinsics, close the block

    pub fn open_block(header: &Header) -> ExtrinsicInclusionMode {
        debug!(
            target: LOG_TARGET,
            "Entering initialize_block. header: {:?}", header
        );

        // Store the transient partial header for updating at the end of the block.
        // This will be removed from storage before the end of the block.
        sp_io::storage::set(HEADER_KEY, &header.encode());

        // Also store the height persistently so it is available when
        // performing pool validations and other off-chain runtime calls.
        sp_io::storage::set(HEIGHT_KEY, &header.number().encode());

        // griffin blocks always allow user transactions.
        ExtrinsicInclusionMode::AllExtrinsics
    }

    pub fn apply_extrinsic(extrinsic: Transaction) -> ApplyExtrinsicResult {
        debug!(
            target: LOG_TARGET,
            "Entering apply_extrinsic: {:?}", extrinsic
        );

        // Append the current extrinsic to the transient list of extrinsics.
        // This will be used when we calculate the extrinsics root at the end of the block.
        let mut extrinsics = sp_io::storage::get(EXTRINSIC_KEY)
            .and_then(|d| <Vec<Vec<u8>>>::decode(&mut &*d).ok())
            .unwrap_or_default();
        extrinsics.push(extrinsic.encode());
        sp_io::storage::set(EXTRINSIC_KEY, &extrinsics.encode());

        // Now actually apply the extrinsic
        Self::apply_griffin_transaction(extrinsic).map_err(|e| {
            log::warn!(
                target: LOG_TARGET,
                "Griffin Transaction did not apply successfully: {:?}",
                e,
            );
            TransactionValidityError::Invalid(e.into())
        })?;

        Ok(Ok(()))
    }

    pub fn close_block() -> Header {
        let mut header = sp_io::storage::get(HEADER_KEY)
            .and_then(|d| Header::decode(&mut &*d).ok())
            .expect("We initialized with header, it never got mutated, qed");

        // the header itself contains the state root, so it cannot be inside the state (circular
        // dependency..). Make sure in execute block path we have the same rule.
        sp_io::storage::clear(HEADER_KEY);

        let extrinsics = sp_io::storage::get(EXTRINSIC_KEY)
            .and_then(|d| <Vec<Vec<u8>>>::decode(&mut &*d).ok())
            .unwrap_or_default();
        let extrinsics_root =
            <Header as HeaderT>::Hashing::ordered_trie_root(extrinsics, StateVersion::V0);
        sp_io::storage::clear(EXTRINSIC_KEY);
        header.set_extrinsics_root(extrinsics_root);

        let raw_state_root = &sp_io::storage::root(StateVersion::V1)[..];
        let state_root = <Header as HeaderT>::Hash::decode(&mut &raw_state_root[..]).unwrap();
        header.set_state_root(state_root);

        debug!(target: LOG_TARGET, "finalizing block {:?}", header);
        header
    }

    // This one is for the Core api. It is used to import blocks authored by foreign nodes.

    pub fn execute_block(block: Block) {
        debug!(
            target: LOG_TARGET,
            "Entering execute_block. block: {:?}", block
        );

        // Store the header. Although we don't need to mutate it, we do need to make
        // info, such as the block height, available to individual pieces. This will
        // be cleared before the end of the block
        sp_io::storage::set(HEADER_KEY, &block.header().encode());

        // Also store the height persistently so it is available when
        // performing pool validations and other off-chain runtime calls.
        sp_io::storage::set(HEIGHT_KEY, &block.header().number().encode());

        // Apply each extrinsic
        for extrinsic in block.extrinsics() {
            match Self::apply_griffin_transaction(extrinsic.clone()) {
                Ok(()) => debug!(
                    target: LOG_TARGET,
                    "Successfully executed extrinsic: {:?}", extrinsic
                ),
                Err(e) => panic!("{:?}", e),
            }
        }

        // Clear the transient header out of storage
        sp_io::storage::clear(HEADER_KEY);

        // Check state root
        let raw_state_root = &sp_io::storage::root(StateVersion::V1)[..];
        let state_root = <Header as HeaderT>::Hash::decode(&mut &raw_state_root[..]).unwrap();
        assert_eq!(
            *block.header().state_root(),
            state_root,
            "state root mismatch"
        );

        // Check extrinsics root.
        let extrinsics = block
            .extrinsics()
            .iter()
            .map(|x| x.encode())
            .collect::<Vec<_>>();
        let extrinsics_root =
            <Header as HeaderT>::Hashing::ordered_trie_root(extrinsics, StateVersion::V0);
        assert_eq!(
            *block.header().extrinsics_root(),
            extrinsics_root,
            "extrinsics root mismatch"
        );
    }

    // This one is the pool api. It is used to make preliminary checks in the transaction pool

    pub fn validate_transaction(
        source: TransactionSource,
        tx: Transaction,
        block_hash: <Block as BlockT>::Hash,
    ) -> TransactionValidity {
        debug!(
            target: LOG_TARGET,
            "Entering validate_transaction. source: {:?}, tx: {:?}, block hash: {:?}",
            source,
            tx,
            block_hash
        );

        let r = Self::validate_griffin_transaction(&tx).map_err(|e| {
                    log::warn!(
                        target: LOG_TARGET,
                        "Griffin Transaction did not validate (in the pool): {:?}",
                        e,
                    );
                    TransactionValidityError::Invalid(e.into())
                });

        debug!(target: LOG_TARGET, "Validation result: {:?}", r);

        r
    }
}
