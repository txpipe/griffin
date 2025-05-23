//! # Executive Module
//!
//! The executive is the main orchestrator for the entire runtime.
//! It has functions that implement the Core, BlockBuilder, and TxPool runtime APIs.
//!
//! It does all the reusable verification of UTXO transactions.

use crate::pallas_applying::{
    babbage::{
        check_ins_not_empty,
        // check_all_ins_in_utxos,
        check_preservation_of_value,
        check_tx_validity_interval,
        check_witness_set,
    },
    utils::BabbageError::*,
    UTxOs,
};
use crate::pallas_codec::utils::CborWrap;
use crate::pallas_primitives::{
    babbage::{
        MintedDatumOption, MintedScriptRef, MintedTransactionBody, MintedTx,
        Tx as PallasTransaction, Value as PallasValue,
    },
    conway::{MintedTx as ConwayMintedTx, TransactionOutput},
};
use crate::uplc::tx::{eval_phase_two, ResolvedInput, SlotConfig};
use crate::{
    checks_interface::{
        babbage_minted_tx_from_cbor, babbage_tx_to_cbor, check_min_coin,
        conway_minted_tx_from_cbor, mk_utxo_for_babbage_tx,
    },
    ensure,
    types::{Block, BlockNumber, DispatchResult, Header, Input, Output, Transaction, UTxOError},
    utxo_set::TransparentUtxoSet,
    EXTRINSIC_KEY, HEADER_KEY, HEIGHT_KEY, LOG_TARGET,
};
use crate::{MILLI_SECS_PER_SLOT, ZERO_SLOT, ZERO_TIME};
use alloc::{collections::btree_set::BTreeSet, string::String, vec::Vec};
use log::debug;
use parity_scale_codec::{Decode, Encode};
use sp_runtime::{
    traits::{BlakeTwo256, Block as BlockT, Extrinsic, Hash as HashT, Header as HeaderT},
    transaction_validity::{
        TransactionLongevity, TransactionSource, TransactionValidity, TransactionValidityError,
        ValidTransaction,
    },
    ApplyExtrinsicResult, ExtrinsicInclusionMode, StateVersion,
};

type OutputInfoList<'a> = Vec<(
    String, // address in string format
    PallasValue,
    Option<MintedDatumOption<'a>>,
    Option<CborWrap<MintedScriptRef<'a>>>,
)>;

/// The executive is in charge of validating transactions for admittance in the
/// pool and in blocks. It is in charge of *executing* transactions, i.e.,
/// applying them to the ledger.
pub struct Executive;

impl Executive
where
    Block: BlockT,
    Transaction: Extrinsic,
{
    /// Checks performed to enter the transaction pool. The response of the node
    /// is essentially determined by the outcome of this function.
    fn pool_checks(mtx: &MintedTx, _utxos: &UTxOs) -> DispatchResult {
        check_ins_not_empty(&mtx.transaction_body.clone())?;
        Ok(())
    }

    /// Checks performed to a transaction with all its requirements satisfied
    /// to be included in a block.
    fn ledger_checks(mtx: &MintedTx, utxos: &UTxOs) -> DispatchResult {
        let tx_body: &MintedTransactionBody = &mtx.transaction_body.clone();
        // Next unneeded since already checked at `apply_griffin_transaction`
        // check_all_ins_in_utxos(tx_body, utxos)?;
        let current_slot = Self::zero_slot() + (Self::block_height() as u64);
        check_tx_validity_interval(tx_body, &current_slot)?;
        check_preservation_of_value(tx_body, utxos)?;
        check_witness_set(mtx, utxos)?;
        check_min_coin(tx_body)?;

        Ok(())
    }

    fn phase_two_checks(tx_cbor_bytes: &Vec<u8>, input_utxos: Vec<Output>) -> DispatchResult {
        let conway_mtx: ConwayMintedTx = conway_minted_tx_from_cbor(&tx_cbor_bytes);
        let pallas_input_utxos = input_utxos
            .iter()
            .map(|ri| TransactionOutput::from(ri.clone()))
            .collect::<Vec<_>>();
        let pallas_resolved_inputs: Vec<ResolvedInput> = conway_mtx
            .transaction_body
            .inputs
            .iter()
            .zip(pallas_input_utxos.iter())
            .map(|(input, output)| ResolvedInput {
                input: input.clone(),
                output: output.clone(),
            })
            .collect();

        let slot_config = SlotConfig {
            zero_time: Self::zero_time(),
            zero_slot: Self::zero_slot(),
            slot_length: MILLI_SECS_PER_SLOT,
        };
        let phase_two_result = eval_phase_two(
            &conway_mtx,
            &pallas_resolved_inputs,
            None,
            None,
            &slot_config,
            false,
            |_| (),
        );
        ensure!(
            phase_two_result.is_ok(),
            UTxOError::PhaseTwo(phase_two_result.unwrap_err())
        );

        Ok(())
    }

    /// Does pool-style validation of a griffin transaction.
    /// Does not commit anything to storage.
    /// This returns Ok even if some inputs are still missing because the tagged transaction pool can handle that.
    /// We later check that there are no missing inputs in `apply_griffin_transaction`.
    ///
    /// The output includes the list of relevant UTxOs to be used for other
    /// checks (in order to avoid a further db search).
    fn validate_griffin_transaction(
        transaction: &Transaction,
    ) -> Result<ValidTransaction, UTxOError> {
        debug!(
            target: LOG_TARGET,
            "validating griffin transaction",
        );

        // Make sure there are no duplicate inputs
        {
            let input_set: BTreeSet<_> = transaction
                .transaction_body
                .inputs
                .iter()
                .map(|o| o.encode())
                .collect();
            ensure!(
                input_set.len() == transaction.transaction_body.inputs.len(),
                UTxOError::Babbage(DuplicateInput)
            );
        }

        let mut tx_outs_info: OutputInfoList = Vec::new();
        let mut input_utxos: Vec<Output> = Vec::new();

        // Add present inputs to a list to be used to produce the local UTxO set.
        // Keep track of any missing inputs for use in the tagged transaction pool
        let mut missing_inputs = Vec::new();
        for input in transaction.transaction_body.inputs.iter() {
            if let Some(u) = TransparentUtxoSet::peek_utxo(&input) {
                tx_outs_info.push((
                    hex::encode(u.address.0.as_slice()),
                    PallasValue::from(u.clone().value),
                    None, // irrelevant for phase 1 checks (always inline datum)
                    None,
                ));
                // Repeated info in tx_outs_info, but we need this type for phase 2 checks
                input_utxos.push(u);
            } else {
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
                UTxOError::Babbage(OutputAlreadyInUTxO)
            );
        }

        // Griffin Tx -> Pallas Tx -> CBOR -> Minted Pallas Tx
        // This last one is used to produce the local UTxO set.
        let pallas_tx: PallasTransaction = <_>::from(transaction.clone());
        let cbor_bytes: Vec<u8> = babbage_tx_to_cbor(&pallas_tx);
        let mtx: MintedTx = babbage_minted_tx_from_cbor(&cbor_bytes);
        let tx_body: &MintedTransactionBody = &mtx.transaction_body.clone();
        let outs_info_clone = tx_outs_info.clone();
        let utxos: UTxOs = mk_utxo_for_babbage_tx(tx_body, outs_info_clone.as_slice());

        Self::pool_checks(&mtx, &utxos)?;

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

        // These checks were done in `apply_griffin_transaction`, but we do them here for simplicity.
        // This might limit the ledger's ability to accept transactions that would be valid
        // in a block, as in chaining.
        Self::ledger_checks(&mtx, &utxos)?;
        Self::phase_two_checks(&cbor_bytes, input_utxos)?;

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
    fn apply_griffin_transaction(transaction: &Transaction) -> DispatchResult {
        debug!(
            target: LOG_TARGET,
            "applying griffin transaction {:?}", transaction
        );

        // Re-do the pre-checks. These should have been done in the pool, but we can't
        // guarantee that foreign nodes do these checks faithfully, so we need to check on-chain.
        let valid_transaction = Self::validate_griffin_transaction(transaction)?;

        // If there are still missing inputs, we cannot execute this,
        // although it would be valid in the pool
        ensure!(
            valid_transaction.requires.is_empty(),
            UTxOError::Babbage(InputNotInUTxO)
        );

        // At this point, all validation is complete, so we can commit the storage changes.
        Self::update_storage(transaction);

        Ok(())
    }

    /// Helper function to update the utxo set according to the given transaction.
    /// This function does absolutely no validation. It assumes that the transaction
    /// has already passed validation. Changes proposed by the transaction are written
    /// blindly to storage.
    fn update_storage(transaction: &Transaction) {
        // Remove verified UTXOs
        for input in &transaction.transaction_body.inputs {
            TransparentUtxoSet::consume_utxo(input);
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

    /// A helper function that allows griffin runtimes to read the start posix time of the first
    /// block, in milliseconds
    pub fn zero_time() -> u64 {
        sp_io::storage::get(ZERO_TIME)
            .and_then(|d| u64::decode(&mut &*d).ok())
            .expect("Failed to read ZERO_TIME from storage.")
    }

    /// A helper function that allows griffin runtimes to read the slot number of the first block
    pub fn zero_slot() -> u64 {
        sp_io::storage::get(ZERO_SLOT)
            .and_then(|d| u64::decode(&mut &*d).ok())
            .expect("Failed to read ZERO_SLOT from storage.")
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
        Self::apply_griffin_transaction(&extrinsic).map_err(|e| {
            log::warn!(
                target: LOG_TARGET,
                "⛔ Griffin Transaction did not validate to be applied due to: {:?}",
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
            match Self::apply_griffin_transaction(&extrinsic) {
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
                "⛔ Griffin Transaction did not validate (in the pool): {:?}",
                e,
            );
            TransactionValidityError::Invalid(e.into())
        });

        debug!(target: LOG_TARGET, "Validation result: {:?}", r);

        r
    }
}
