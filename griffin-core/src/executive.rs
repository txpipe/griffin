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
    conway::{MintedTx as ConwayMintedTx, TransactionInput, TransactionOutput},
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
        check_preservation_of_value(tx_body, utxos)?;
        check_witness_set(mtx, utxos)?;
        check_min_coin(tx_body)?;

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
    ) -> Result<(OutputInfoList, ValidTransaction), UTxOError> {
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
        let mut resolved_inputs: Vec<Output> = Vec::new();

        // Add present inputs to a list to be used to produce the local UTxO set.
        // Keep track of any missing inputs for use in the tagged transaction pool
        let mut missing_inputs = Vec::new();
        for input in transaction.transaction_body.inputs.iter() {
            if let Some(u) = TransparentUtxoSet::peek_utxo(&input) {
                tx_outs_info.push((
                    hex::encode(u.address.0.as_slice()),
                    PallasValue::from(u.clone().value),
                    None,
                    None,
                ));
                resolved_inputs.push(u);
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
            return Ok((
                tx_outs_info,
                ValidTransaction {
                    requires: missing_inputs,
                    provides,
                    priority: 0,
                    longevity: TransactionLongevity::MAX,
                    propagate: true,
                },
            ));
        }

        // Run phase-two validation
        let conway_mtx: ConwayMintedTx = conway_minted_tx_from_cbor(&cbor_bytes);
        let pallas_inputs = transaction
            .transaction_body
            .inputs
            .iter()
            .map(|i| TransactionInput::from(i.clone()))
            .collect::<Vec<_>>();
        let pallas_resolved_inputs = resolved_inputs
            .iter()
            .map(|ri| TransactionOutput::from(ri.clone()))
            .collect::<Vec<_>>();
        let pallas_input_utxos: Vec<ResolvedInput> = pallas_inputs
            .iter()
            .zip(pallas_resolved_inputs.iter())
            .map(|(input, output)| ResolvedInput {
                input: input.clone(),
                output: output.clone(),
            })
            .collect();

        let phase_two_result = eval_phase_two(
            &conway_mtx,
            &pallas_input_utxos,
            None,
            None,
            &SlotConfig::default(),
            false,
            |_| (),
        );
        ensure!(
            phase_two_result.is_ok(),
            UTxOError::Babbage(PhaseTwoValidationError)
        );

        // Return the valid transaction
        Ok((
            tx_outs_info,
            ValidTransaction {
                requires: Vec::new(),
                provides,
                priority: 0,
                longevity: TransactionLongevity::MAX,
                propagate: true,
            },
        ))
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
        let (outs_info, valid_transaction) = Self::validate_griffin_transaction(transaction)?;

        // If there are still missing inputs, we cannot execute this,
        // although it would be valid in the pool
        ensure!(
            valid_transaction.requires.is_empty(),
            UTxOError::Babbage(InputNotInUTxO)
        );

        // FIXME: Duplicate code
        // Griffin Tx -> Pallas Tx -> CBOR -> Minted Pallas Tx
        // This last one is used to produce the local UTxO set.
        let pallas_tx: PallasTransaction = <_>::from(transaction.clone());
        let cbor_bytes: Vec<u8> = babbage_tx_to_cbor(&pallas_tx);
        let mtx: MintedTx = babbage_minted_tx_from_cbor(&cbor_bytes);
        let tx_body: &MintedTransactionBody = &mtx.transaction_body.clone();
        let utxos: UTxOs = mk_utxo_for_babbage_tx(tx_body, outs_info.as_slice());

        Self::ledger_checks(&mtx, &utxos)?;

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

        let r = Self::validate_griffin_transaction(&tx)
            .map_err(|e| {
                log::warn!(
                    target: LOG_TARGET,
                    "⛔ Griffin Transaction did not validate (in the pool): {:?}",
                    e,
                );
                TransactionValidityError::Invalid(e.into())
            })
            .map(|x| x.1);

        debug!(target: LOG_TARGET, "Validation result: {:?}", r);

        r
    }
}

#[test]
fn test_eval_order_resolve() {
    use crate::checks_interface::conway_minted_tx_from_cbor;
    use crate::pallas_codec::utils::MaybeIndefArray::Def;
    use crate::pallas_crypto::hash::Hash;
    use crate::pallas_primitives::conway::{
        Constr, MintedTx as ConwayMintedTx, PlutusData as PallasPlutusData, TransactionInput,
        TransactionOutput,
    };
    use crate::types::{
        Address, AssetClass, AssetName, Datum, ExUnits, Input, OrderDatum, Output, PlutusData,
        PlutusScript, Redeemer, RedeemerTag, VKeyWitness, Value,
    };
    use crate::uplc::tx::{eval_phase_two, ResolvedInput, SlotConfig};
    use crate::H224;
    use core::str::FromStr;
    use sp_core::H256;

    let inputs = vec![
        Input {
            tx_hash: H256::from_slice(
                hex::decode("62b64a5cca307624cd90ff002ac26c3d3faa9dec56f1f360954120ffc38306e8")
                    .unwrap()
                    .as_slice(),
            ),
            index: 0,
        },
        Input {
            tx_hash: H256::from_slice(
                hex::decode("27d67023bde9c18c75fe5939a88d3771f061d82cfa3b9bce12d1df9118b74a8d")
                    .unwrap()
                    .as_slice(),
            ),
            index: 1,
        },
    ];

    let token_a_policy = H224::from(
        Hash::from_str("0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005").unwrap(),
    );
    let token_a_name = "tokenA";
    let token_b_policy = H224::from(
        Hash::from_str("0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005").unwrap(),
    );
    let token_b_name = "tokenB";
    let token_b_amount: u64 = 2;

    let sender_payment_hash = H224::from(
        Hash::from_str("01e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4").unwrap(),
    );
    let order_datum = OrderDatum::Ok {
        sender_payment_hash: sender_payment_hash,
        ordered_class: AssetClass {
            policy_id: token_b_policy,
            asset_name: AssetName::from(token_b_name.to_string()),
        },
        ordered_amount: token_b_amount,
    };

    let script = hex::decode("59036a01000032323232323232232322322533300732533300830063009375400826464a66601a6020004266e3c004dd7180198061baa3003300c37540122c6eb8c038004dd618069807180718071807180718071807180718051baa3001300a3754004264646464646464a66601e66ebcc020c044dd5003180399809980399809980418089baa30083011375401c97ae0330134c103d87a80004bd7008008a50533300e3375e600c66024602600666024602600497ae0300730103754600860206ea8c01cc040dd5006899b89375a600860206ea8c010c040dd5180398081baa00d00114a06eb4c048c04c004c048004c94ccc030cdc79bae3005300e3754600a601c6ea8c008c038dd5180298071baa00b488100132325333011301400213233013301400233013301400133013301430150014bd70180a0008b1bac3012001300137566004601c6ea800c4c8c94ccc044c0500084c8cc04cc050008cc04cc050004cc04cc050c0540052f5c060280022c6eb0c048004c004c8cc004004dd5980198079baa00422533301100114bd6f7b630099191919299980919b8f489000021003133016337606ea4008dd3000998030030019bab3013003375c6022004602a00460260024646600200200444a666022002297ae01323332223233001001003225333017001100313233019374e660326ea4018cc064dd49bae30160013301937506eb4c05c0052f5c066006006603600460320026eb8c040004dd5980880099801801980a8011809800918081808800992999805180418059baa0011300f300c37540022c64a66601a0022980103d87a8000130023300e300f0014bd701bac300e300f300f300b3754600460166ea800cdd2a40004601a00229309b2b19299980318020008a99980498041baa00214985854ccc018cdc3a40040022a66601260106ea8008526161630063754002a666006600260086ea80084c8c94ccc020c02c0084c9265333005300330063754002264646464a666018601e004264932999804980398051baa001132323232533301030130021324994ccc034c02cc038dd5001899191919299980a180b8010a4c2c6eb8c054004c054008dd7180980098079baa0031616375a60220026022004601e00260166ea80045858c034004c034008dd7180580098039baa00116163009001300537540042c6e1d20005734aae7555cf2ab9f5740ae855d11").unwrap();

    let resolved_inputs = vec![
        Output {
            address: Address(
                hex::decode("70b4dcdce0cc9e1ecbc4f16cf14e2e15e189b6c05d48f69ffdfac34395").unwrap(),
            ),
            value: Value::from((
                314,
                token_a_policy,
                AssetName::from(token_a_name.to_string()),
                1,
            )),
            datum_option: Some(Datum::from(order_datum)),
        },
        Output {
            address: Address(
                hex::decode("6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4").unwrap(),
            ),
            value: Value::Coin(3),
            datum_option: None,
        },
    ];

    let outputs = vec![Output {
        address: Address(
            hex::decode("6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4").unwrap(),
        ),
        value: Value::from((
            10,
            token_b_policy,
            AssetName::from(token_b_name.to_string()),
            2,
        )),
        datum_option: None,
    }];

    let pallas_inputs = inputs
        .iter()
        .map(|i| TransactionInput::from(i.clone()))
        .collect::<Vec<_>>();
    let pallas_resolved_inputs = resolved_inputs
        .iter()
        .map(|ri| TransactionOutput::from(ri.clone()))
        .collect::<Vec<_>>();

    let resolve_redeemer = Redeemer {
        tag: RedeemerTag::Spend,
        index: 1,
        data: PlutusData::from(PallasPlutusData::Constr(Constr {
            tag: 122,
            any_constructor: None,
            fields: Def([].to_vec()),
        })),
        ex_units: ExUnits {
            mem: 661056,
            steps: 159759842,
        },
    };

    let mut transaction = Transaction::from((Vec::new(), Vec::new()));
    for input in inputs {
        transaction.transaction_body.inputs.push(input.clone());
    }
    for output in outputs {
        transaction.transaction_body.outputs.push(output.clone());
    }

    let vkeywitness = VKeyWitness {
        vkey: hex::decode("F6E9814CE6626EB532372B1740127E153C28D643A9384F51B1B0229AEDA43717").unwrap(),
        signature: hex::decode("b22b78b86e64a5849f51df512289c5be0c463cce6966caaecda265be3ed37b5c68c04dad7616bfa78a2e1235eb80c8b9b366c0a16a131fbcfebce8b35382b90d").unwrap()
    };
    let sign: H224 = H224::from(
        Hash::from_str("01e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4").unwrap(),
    );

    transaction.transaction_body.required_signers = Some(vec![sign]);
    transaction.transaction_body.validity_interval_start = Some(82651727);
    transaction.transaction_witness_set.vkeywitness = Some(vec![vkeywitness]);
    transaction.transaction_witness_set.redeemer = Some(vec![resolve_redeemer]);
    transaction.transaction_witness_set.plutus_script = Some(vec![PlutusScript(script)]);

    let pallas_tx: PallasTransaction = <_>::from(transaction.clone());
    let cbor_bytes: Vec<u8> = babbage_tx_to_cbor(&pallas_tx);
    let mtx: ConwayMintedTx = conway_minted_tx_from_cbor(&cbor_bytes);

    let input_utxos: Vec<ResolvedInput> = pallas_inputs
        .iter()
        .zip(pallas_resolved_inputs.iter())
        .map(|(input, output)| ResolvedInput {
            input: input.clone(),
            output: output.clone(),
        })
        .collect();

    let redeemers = eval_phase_two(
        &mtx,
        &input_utxos,
        None,
        None,
        &SlotConfig::default(),
        false,
        |_| (),
    )
    .unwrap();
    assert_eq!(redeemers.len(), 1);
}

#[test]
fn test_eval_order_cancel() {
    use crate::checks_interface::conway_minted_tx_from_cbor;
    use crate::pallas_codec::utils::MaybeIndefArray::Def;
    use crate::pallas_crypto::hash::Hash;
    use crate::pallas_primitives::conway::{
        Constr, MintedTx as ConwayMintedTx, PlutusData as PallasPlutusData, TransactionInput,
        TransactionOutput,
    };
    use crate::types::{
        Address, AssetClass, AssetName, Datum, ExUnits, Input, OrderDatum, Output, PlutusData,
        PlutusScript, Redeemer, RedeemerTag, VKeyWitness, Value,
    };
    use crate::uplc::tx::{eval_phase_two, ResolvedInput, SlotConfig};
    use crate::H224;
    use core::str::FromStr;
    use sp_core::H256;

    let inputs = vec![Input {
        tx_hash: H256::from_slice(
            hex::decode("62b64a5cca307624cd90ff002ac26c3d3faa9dec56f1f360954120ffc38306e8")
                .unwrap()
                .as_slice(),
        ),
        index: 0,
    }];

    let token_b_policy = H224::from(
        Hash::from_str("0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005").unwrap(),
    );
    let token_b_name = "tokenB";
    let token_b_amount: u64 = 2;

    let sender_payment_hash = H224::from(
        Hash::from_str("5b6de1be218ebb35fc08b2983e3a1d72aec969c8d2a6301212e2ea9a").unwrap(),
    );

    let order_datum = OrderDatum::Ok {
        sender_payment_hash: sender_payment_hash,
        ordered_class: AssetClass {
            policy_id: token_b_policy,
            asset_name: AssetName::from(token_b_name.to_string()),
        },
        ordered_amount: token_b_amount,
    };

    let resolved_inputs = vec![Output {
        address: Address(
            hex::decode("70b4dcdce0cc9e1ecbc4f16cf14e2e15e189b6c05d48f69ffdfac34395").unwrap(),
        ),
        value: Value::Coin(314),
        datum_option: Some(Datum::from(order_datum)),
    }];

    let pallas_inputs = inputs
        .iter()
        .map(|i| TransactionInput::from(i.clone()))
        .collect::<Vec<_>>();
    let pallas_resolved_inputs = resolved_inputs
        .iter()
        .map(|ri| TransactionOutput::from(ri.clone()))
        .collect::<Vec<_>>();

    let script = hex::decode("59036a01000032323232323232232322322533300732533300830063009375400826464a66601a6020004266e3c004dd7180198061baa3003300c37540122c6eb8c038004dd618069807180718071807180718071807180718051baa3001300a3754004264646464646464a66601e66ebcc020c044dd5003180399809980399809980418089baa30083011375401c97ae0330134c103d87a80004bd7008008a50533300e3375e600c66024602600666024602600497ae0300730103754600860206ea8c01cc040dd5006899b89375a600860206ea8c010c040dd5180398081baa00d00114a06eb4c048c04c004c048004c94ccc030cdc79bae3005300e3754600a601c6ea8c008c038dd5180298071baa00b488100132325333011301400213233013301400233013301400133013301430150014bd70180a0008b1bac3012001300137566004601c6ea800c4c8c94ccc044c0500084c8cc04cc050008cc04cc050004cc04cc050c0540052f5c060280022c6eb0c048004c004c8cc004004dd5980198079baa00422533301100114bd6f7b630099191919299980919b8f489000021003133016337606ea4008dd3000998030030019bab3013003375c6022004602a00460260024646600200200444a666022002297ae01323332223233001001003225333017001100313233019374e660326ea4018cc064dd49bae30160013301937506eb4c05c0052f5c066006006603600460320026eb8c040004dd5980880099801801980a8011809800918081808800992999805180418059baa0011300f300c37540022c64a66601a0022980103d87a8000130023300e300f0014bd701bac300e300f300f300b3754600460166ea800cdd2a40004601a00229309b2b19299980318020008a99980498041baa00214985854ccc018cdc3a40040022a66601260106ea8008526161630063754002a666006600260086ea80084c8c94ccc020c02c0084c9265333005300330063754002264646464a666018601e004264932999804980398051baa001132323232533301030130021324994ccc034c02cc038dd5001899191919299980a180b8010a4c2c6eb8c054004c054008dd7180980098079baa0031616375a60220026022004601e00260166ea80045858c034004c034008dd7180580098039baa00116163009001300537540042c6e1d20005734aae7555cf2ab9f5740ae855d11").unwrap();
    let cancel_redeemer = Redeemer {
        tag: RedeemerTag::Spend,
        index: 0,
        data: PlutusData::from(PallasPlutusData::Constr(Constr {
            tag: 121,
            any_constructor: None,
            fields: Def([].to_vec()),
        })),
        ex_units: ExUnits {
            mem: 661056,
            steps: 159759842,
        },
    };

    let mut transaction = Transaction::from((Vec::new(), Vec::new()));
    for input in inputs {
        transaction.transaction_body.inputs.push(input.clone());
    }
    transaction.transaction_body.required_signers = Some(vec![sender_payment_hash]);
    transaction.transaction_body.validity_interval_start = Some(82651727);
    let vkeywitness = VKeyWitness {
        vkey: hex::decode("F6E9814CE6626EB532372B1740127E153C28D643A9384F51B1B0229AEDA43717").unwrap(),
        signature: hex::decode("A4ACDA77397F7A80B21FA17AE95FCC99C255069B8135897BA8A7A5EC0E829DBA91171FBF794C1A5E6249263B04075C659BDEBA1B1E10E38F734539626BFF6905").unwrap()
    };
    transaction.transaction_witness_set.vkeywitness = Some(vec![vkeywitness]);
    transaction.transaction_witness_set.redeemer = Some(vec![cancel_redeemer]);
    transaction.transaction_witness_set.plutus_script = Some(vec![PlutusScript(script)]);

    let pallas_tx: PallasTransaction = <_>::from(transaction.clone());
    let cbor_bytes: Vec<u8> = babbage_tx_to_cbor(&pallas_tx);
    let mtx: ConwayMintedTx = conway_minted_tx_from_cbor(&cbor_bytes);

    let input_utxos: Vec<ResolvedInput> = pallas_inputs
        .iter()
        .zip(pallas_resolved_inputs.iter())
        .map(|(input, output)| ResolvedInput {
            input: input.clone(),
            output: output.clone(),
        })
        .collect();

    let redeemers = eval_phase_two(
        &mtx,
        &input_utxos,
        None,
        None,
        &SlotConfig::default(),
        false,
        |_| (),
    )
    .unwrap();
    assert_eq!(redeemers.len(), 1);
}

#[test]
fn test_eval_vesting() {
    /* TESTED CONTRACT:

    mkParameterizedVestingValidator :: VestingParams -> () -> () -> ScriptContext -> Bool
    mkParameterizedVestingValidator params () () ctx =
        traceIfFalse "beneficiary's signature missing" signedByBeneficiary &&
        traceIfFalse "deadline not reached" deadlineReached
    where
        info :: TxInfo
        info = scriptContextTxInfo ctx

        signedByBeneficiary :: Bool
        signedByBeneficiary = txSignedBy info $ beneficiary params

        deadlineReached :: Bool
        deadlineReached = contains (from $ deadline params) $ txInfoValidRange info

    */
    use crate::checks_interface::conway_minted_tx_from_cbor;
    use crate::pallas_codec::utils::{
        Int,
        MaybeIndefArray::{Def, Indef},
    };
    use crate::pallas_crypto::hash::Hash;
    use crate::pallas_primitives::conway::{
        BigInt, BoundedBytes, Constr, MintedTx as ConwayMintedTx, PlutusData as PallasPlutusData,
        TransactionInput, TransactionOutput,
    };
    use crate::types::{
        Address, Datum, ExUnits, Input, Output, PlutusData, PlutusScript, Redeemer, RedeemerTag,
        Value,
    };
    use crate::uplc::tx::{eval_phase_two, ResolvedInput, SlotConfig};
    use crate::H224;
    use core::str::FromStr;
    use sp_core::H256;

    let inputs = vec![
        Input {
            tx_hash: H256::from_slice(
                hex::decode("4D622E9CF18528954A844948A8D28348B584907BC92D97592DD4ABEDB2C41D20")
                    .unwrap()
                    .as_slice(),
            ),
            index: 0,
        },
        Input {
            tx_hash: H256::from_slice(
                hex::decode("4DDF0879BD59269F448C9B1719ECB0607EC7DCDBC22AF8A188BCFEB4618B7593")
                    .unwrap()
                    .as_slice(),
            ),
            index: 1,
        },
    ];

    let datum = PallasPlutusData::Constr(Constr {
        tag: 121,
        any_constructor: None,
        fields: Indef(
            [
                PallasPlutusData::BoundedBytes(BoundedBytes(
                    hex::decode("5b6de1be218ebb35fc08b2983e3a1d72aec969c8d2a6301212e2ea9a")
                        .unwrap(),
                )),
                PallasPlutusData::BigInt(BigInt::Int(Int(minicbor::data::Int::from(
                    1679184000000 as u64,
                )))),
            ]
            .to_vec(),
        ),
    });

    let resolved_inputs = vec![
        Output {
            address: Address(
                hex::decode("7089A87CE851285C4FEBAD4AAC83F1B1D9A25E72B3342F6C5FE0B27A8F").unwrap(),
            ),
            value: Value::Coin(314),
            datum_option: Some(Datum(PlutusData::from(datum.clone()).0)),
        },
        Output {
            address: Address(
                hex::decode("005b6de1be218ebb35fc08b2983e3a1d72aec969c8d2a6301212e2ea9a29f8f56c3886af095e6b2413fa1c1e81dfe373106928ecbe38dce4dc").unwrap(),
            ),
            value: Value::Coin(3),
            datum_option: None,
        },
    ];

    let pallas_inputs = inputs
        .iter()
        .map(|i| TransactionInput::from(i.clone()))
        .collect::<Vec<_>>();
    let pallas_resolved_inputs = resolved_inputs
        .iter()
        .map(|o| TransactionOutput::from(o.clone()))
        .collect::<Vec<_>>();

    let script = hex::decode("590b2d0100003232323322323233223232323232323233223233223232323232323232333222323232322323222323253353232323253355335323235002222222222222533533355301a12001321233001225335002210031001002502c25335333573466e3c0380040ec0e84d40b8004540b4010840ec40e4d401488009400440b04cd5ce2491f62656e65666963696172792773207369676e6174757265206d697373696e670002b15335323232350022235002223500522350022253335333501900b00600215335001153350051333501800b00300710361333501800b00300710361333501800b00300735500322222222222200533501433501635029350052200102d335015502802d123333333300122333573466e1c0080040bc0b8894cd4ccd5cd19b8700200102f02e101515335333573466e240080040bc0b8404c405088ccd5cd19b8800200102f02e22333573466e240080040bc0b888ccd5cd19b8900200102e02f22333573466e200080040b80bc894cd4ccd5cd19b8900200102f02e10011002225335333573466e240080040bc0b84008400440b04cd5ce248114646561646c696e65206e6f7420726561636865640002b102b135001220023333573466e1cd55cea80224000466442466002006004646464646464646464646464646666ae68cdc39aab9d500c480008cccccccccccc88888888888848cccccccccccc00403403002c02802402001c01801401000c008cd408c090d5d0a80619a8118121aba1500b33502302535742a014666aa04eeb94098d5d0a804999aa813bae502635742a01066a0460606ae85401cccd5409c0c5d69aba150063232323333573466e1cd55cea80124000466a0486464646666ae68cdc39aab9d5002480008cd40a8cd40edd69aba15002303e357426ae8940088c98c8100cd5ce02182101f09aab9e5001137540026ae854008c8c8c8cccd5cd19b8735573aa0049000119a81499a81dbad35742a004607c6ae84d5d1280111931902019ab9c04304203e135573ca00226ea8004d5d09aba2500223263203c33573807e07c07426aae7940044dd50009aba1500533502375c6ae854010ccd5409c0b48004d5d0a801999aa813bae200135742a004605e6ae84d5d1280111931901c19ab9c03b03a036135744a00226ae8940044d5d1280089aba25001135744a00226ae8940044d5d1280089aba25001135744a00226ae8940044d55cf280089baa00135742a008603e6ae84d5d1280211931901519ab9c02d02c0283333573466e1cd55ce9baa0054800080ac8c98c80a4cd5ce0160158139999ab9a3370e6aae7540192000233221233001003002375c6ae854018dd69aba135744a00c464c6405066ae700ac0a809840a44c98c809ccd5ce2490350543500029135573ca00226ea80044d55cf280089baa00132001355023221122253350011350032200122133350052200230040023335530071200100500400112223500222350032253335333500800700400215335003100110261025102612223232323253335006215333500621533350082130044984c00d261533350072130044984c00d26100d100b1533350072130044984c00d261533350062130044984c00d26100c1533350052100a100b100915333500521533350072130054984c011261533350062130054984c01126100c100a1533350062130054984c011261533350052130054984c01126100b2533350052153335007215333500721333500b00a002001161616100b153335006215333500621333500a009002001161616100a10092533350042153335006215333500621333500a009002001161616100a1533350052153335005213335009008002001161616100910082533350032153335005215333500521333500900800200116161610091533350042153335004213335008007002001161616100810072533350022153335004215333500421333500800700200116161610081533350032153335003213335007006002001161616100710061235001222222220071222003122200212220011221233001003002122123300100300212212330010030021232230023758002640026aa034446666aae7c004940288cd4024c010d5d080118019aba200201a232323333573466e1cd55cea80124000466442466002006004601c6ae854008c014d5d09aba2500223263201833573803603402c26aae7940044dd50009191919191999ab9a3370e6aae75401120002333322221233330010050040030023232323333573466e1cd55cea80124000466442466002006004602e6ae854008cd403c058d5d09aba2500223263201d33573804003e03626aae7940044dd50009aba150043335500875ca00e6ae85400cc8c8c8cccd5cd19b875001480108c84888c008010d5d09aab9e500323333573466e1d4009200223212223001004375c6ae84d55cf280211999ab9a3370ea00690001091100191931900f99ab9c02202101d01c01b135573aa00226ea8004d5d0a80119a805bae357426ae8940088c98c8064cd5ce00e00d80b89aba25001135744a00226aae7940044dd5000899aa800bae75a224464460046eac004c8004d5405c88c8cccd55cf80112804119a8039991091980080180118031aab9d5002300535573ca00460086ae8800c0604d5d080088910010910911980080200189119191999ab9a3370ea002900011a80398029aba135573ca00646666ae68cdc3a801240044a00e464c6402866ae7005c0580480444d55cea80089baa0011212230020031122001232323333573466e1d400520062321222230040053007357426aae79400c8cccd5cd19b875002480108c848888c008014c024d5d09aab9e500423333573466e1d400d20022321222230010053007357426aae7940148cccd5cd19b875004480008c848888c00c014dd71aba135573ca00c464c6402466ae7005405004003c0380344d55cea80089baa001232323333573466e1cd55cea80124000466442466002006004600a6ae854008dd69aba135744a004464c6401c66ae700440400304d55cf280089baa0012323333573466e1cd55cea800a400046eb8d5d09aab9e500223263200c33573801e01c01426ea80048c8c8c8c8c8cccd5cd19b8750014803084888888800c8cccd5cd19b875002480288488888880108cccd5cd19b875003480208cc8848888888cc004024020dd71aba15005375a6ae84d5d1280291999ab9a3370ea00890031199109111111198010048041bae35742a00e6eb8d5d09aba2500723333573466e1d40152004233221222222233006009008300c35742a0126eb8d5d09aba2500923333573466e1d40192002232122222223007008300d357426aae79402c8cccd5cd19b875007480008c848888888c014020c038d5d09aab9e500c23263201533573803002e02602402202001e01c01a26aae7540104d55cf280189aab9e5002135573ca00226ea80048c8c8c8c8cccd5cd19b875001480088ccc888488ccc00401401000cdd69aba15004375a6ae85400cdd69aba135744a00646666ae68cdc3a80124000464244600400660106ae84d55cf280311931900719ab9c01101000c00b135573aa00626ae8940044d55cf280089baa001232323333573466e1d400520022321223001003375c6ae84d55cf280191999ab9a3370ea004900011909118010019bae357426aae7940108c98c802ccd5ce00700680480409aab9d50011375400224464646666ae68cdc3a800a40084a00c46666ae68cdc3a8012400446a010600c6ae84d55cf280211999ab9a3370ea00690001091100111931900619ab9c00f00e00a009008135573aa00226ea8004484888c00c010448880048c8cccd5cd19b8750014800880188cccd5cd19b8750024800080188c98c8018cd5ce00480400200189aab9d37540029309100109100089000a490350543100112323001001223300330020020011").unwrap();
    let redeemer = Redeemer {
        tag: RedeemerTag::Spend,
        index: 0,
        data: PlutusData::from(PallasPlutusData::Constr(Constr {
            tag: 121,
            any_constructor: None,
            fields: Def([].to_vec()),
        })),
        ex_units: ExUnits {
            mem: 661056,
            steps: 159759842,
        },
    };

    let mut transaction = Transaction::from((Vec::new(), Vec::new()));
    for input in inputs {
        transaction.transaction_body.inputs.push(input.clone());
    }

    let sign: H224 = H224::from(
        Hash::from_str("5b6de1be218ebb35fc08b2983e3a1d72aec969c8d2a6301212e2ea9a").unwrap(),
    );
    transaction.transaction_body.required_signers = Some(vec![sign]);
    transaction.transaction_body.validity_interval_start = Some(82651727);
    transaction.transaction_witness_set.redeemer = Some(vec![redeemer]);
    transaction.transaction_witness_set.plutus_script = Some(vec![PlutusScript(script)]);
    let pallas_tx: PallasTransaction = <_>::from(transaction.clone());
    let cbor_bytes: Vec<u8> = babbage_tx_to_cbor(&pallas_tx);
    let mtx: ConwayMintedTx = conway_minted_tx_from_cbor(&cbor_bytes);

    let input_utxos: Vec<ResolvedInput> = pallas_inputs
        .iter()
        .zip(pallas_resolved_inputs.iter())
        .map(|(input, output)| ResolvedInput {
            input: input.clone(),
            output: output.clone(),
        })
        .collect();

    let slot_config = SlotConfig {
        zero_time: 1660003200000, // Preview network
        zero_slot: 0,
        slot_length: 1000,
    };

    let redeemers =
        eval_phase_two(&mtx, &input_utxos, None, None, &slot_config, false, |_| ()).unwrap();
    assert_eq!(redeemers.len(), 1);
}
