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
fn test_eval_order_start() {
    use crate::checks_interface::conway_minted_tx_from_cbor;
    use crate::pallas_codec::utils::MaybeIndefArray::Def;
    use crate::pallas_crypto::hash::Hash;
    use crate::pallas_primitives::conway::{
        Constr, MintedTx as ConwayMintedTx, PlutusData as PallasPlutusData,
    };
    use crate::types::{
        compute_plutus_v2_script_hash, Address, AssetClass, AssetName, Datum, ExUnits, Multiasset,
        OrderDatum, Output, PlutusData, PlutusScript, Redeemer, RedeemerTag, VKeyWitness, Value,
    };
    use crate::uplc::tx::{eval_phase_two, SlotConfig};
    use crate::H224;
    use core::str::FromStr;

    let script = PlutusScript(hex::decode("59080c010000323232323232322253232323330063001300737540082a66600c646464646464a66601866e1c005200114a2264646464a666026602c004264646464646464a66602ea66602e60260182a66602e60146eb8c044c064dd5002899b8f00d375c600660326ea80145280a501533301700415333017001100214a0294052819b8848000dd69801180c1baa30023018375400a66e1cc94ccc058c048c05cdd50008a400026eb4c06cc060dd500099299980b1809180b9baa00114c0103d87a8000132330010013756603860326ea8008894ccc06c004530103d87a80001323232533301b3371e0226eb8c07000c4c060cc07cdd4000a5eb804cc014014008dd6980e001180f801180e80099198008009bab30023018375400e44a666034002298103d87a80001323232533301a300d375c60360062602e6603c6e980052f5c026600a00a0046eacc06c008c078008c0700040288c068c06c004cc88c8cc00400400c894ccc068004528099299980c19b8f375c603a00400829444cc00c00c004c074004dd6180c180c980c980c980c980c980c980c980c980a9baa300d301537540226eb8c034c054dd5001180b980c001180b00098091baa332253330123370e900218099baa001132325333017301a0021320025333014300f30153754002264646464a666036603c00426464931804801299980c1809980c9baa003132323232533301f30220021324994ccc070c05cc074dd50008991919192999811981300109924c60200062c6eb4c090004c090008c088004c078dd50008b0b181000098100011bae301e001301a37540062c2c603800260380046034002602c6ea80045858c060004c050dd50008b12999808980618091baa0011323232325333018301b002149858dd7180c800980c8011bae3017001301337540022c600860246ea800458c050004c8cc004004dd6180198089baa30093011375401a44a666026002297ae0132325333012325333013300f301437540022600c6eb8c060c054dd50008a50300c30143754601860286ea80084cc058008cc0100100044cc010010004c05c008c054004dc780291809180998098009bad30103011002375c601e002601e0046eb8c034004c8c94ccc030c03c008400458dd61806800991980080099198008009bab300e300f300f300f300f300b3754600660166ea801c894ccc03400452f5bded8c0264646464a66601c66e3d2201000021003133012337606ea4008dd3000998030030019bab300f003375c601a0046022004601e00244a666018002297ae01323332223233001001003225333012001100313233014374e660286ea4018cc050dd49bae30110013301437506eb4c0480052f5c066006006602c00460280026eb8c02c004dd598060009980180198080011807000918060008a4c26cac26644644a666014646464646464646464a666026a666026601c60286ea80304c8c94ccc060c06c0084cdc78009bae300b301737546016602e6ea805058dd7180c8009bac301830193019301930193019301930193019301537546012602a6ea80284c8c8c8c8c94ccc060cdd79807180d1baa00530153301c30153301c300e301a3754601c60346ea805d2f5c06603898103d87a80004bd7008008a5053330173375e602866036603800666036603800497ae0300d30193754600c60326ea8c034c064dd500b099b89375a600c60326ea8c018c064dd51806980c9baa01600114a06eb4c06cc070004c06c0054ccc050cdc79bae300a301637546014602c6ea8c00cc058dd51805180b1baa013488100132325333019301c0021323301b301c0023301b301c0013301b301c301d0014bd70180e0008b1bac301a001300937566006602c6ea80044c8c94ccc064c0700084c8cc06cc070008cc06cc070004cc06cc070c0740052f5c060380022c6eb0c068004c024cc020dd59801980b1baa001488100325333014300f3015375400226032602c6ea800458c94ccc05c004530103d87a8000130113301830190014bd701bac301830193019301537546012602a6ea80284004528299980919b87375a602e603000690008a99980919b8f004375c601060286ea8c004c050dd5008899b8f002375c600260286ea8c004c050dd50088a5014a04602e60300026eb8c054004c054008dd7180980099192999809180a80108008b1bac3013001300233001375660246026602660266026601e6ea8c00cc03cdd500224410022323300100100322533301300114bd6f7b630099191919299980a19b8f0070021003133018337606ea4008dd3000998030030019bab3015003375c6026004602e004602a0024646600200200444a666022002297ae01323332223233001001003225333017001100313233019374e660326ea4018cc064dd49bae30160013301937506eb4c05c0052f5c066006006603600460320026eb8c040004dd5980880099801801980a8011809800918080008a4c26cac64a66601260080022a66601860166ea8008526161533300930050011533300c300b37540042930b0b18049baa00132533300730023008375400c264646464a66601c6022004264649318030012999805980318061baa003132323232533301230150021324994ccc03cc028c040dd5000899191919299980b180c80109924c601a0062c6eb4c05c004c05c008c054004c044dd50008b0b180980098098011bae3011001300d37540062c2c601e002601e004601a00260126ea80185894ccc01cc008c020dd5000899191919299980718088010a4c2c6eb8c03c004c03c008dd7180680098049baa00116300b300837540086e1d2000370e90011ba5480015cd2ab9d5573caae7d5d02ba157441").unwrap());
    let script_hash = compute_plutus_v2_script_hash(script.clone());

    let token_a_policy = H224::from(
        Hash::from_str("0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005").unwrap(),
    );
    let token_a_name = AssetName::from("tokenA".to_string());
    let token_b_policy = H224::from(
        Hash::from_str("0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005").unwrap(),
    );
    let token_b_name = AssetName::from("tokenB".to_string());
    let token_b_amount: u64 = 2;

    let sender_payment_hash = H224::from(
        Hash::from_str("01e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4").unwrap(),
    );
    let control_token_policy = script_hash;
    let control_token_name = AssetName::from("controlToken".to_string());
    let _mint = Some(Multiasset::from((
        control_token_policy,
        control_token_name.clone(),
        -1,
    )));

    let order_datum = OrderDatum::Ok {
        sender_payment_hash: sender_payment_hash,
        control_token_class: AssetClass {
            policy_id: control_token_policy,
            asset_name: control_token_name.clone(),
        },
        ordered_class: AssetClass {
            policy_id: token_b_policy,
            asset_name: token_b_name,
        },
        ordered_amount: token_b_amount,
    };

    let outputs = vec![Output {
        address: Address(hex::decode("70".to_owned() + &hex::encode(script_hash)).unwrap()),
        value: Value::from((token_a_policy, token_a_name, 1))
            + Value::from((control_token_policy, control_token_name.clone(), 1))
            + Value::Coin(10),
        datum_option: Some(Datum::from(order_datum)),
    }];

    let mut transaction = Transaction::from((Vec::new(), Vec::new()));
    for output in outputs {
        transaction.transaction_body.outputs.push(output.clone());
    }

    let vkeywitness = VKeyWitness {
        vkey: hex::decode("7b155093789404780735f4501c576e9f6e2b0a486cdec70e03e1ef8b9ef99274").unwrap(),
        signature: hex::decode("9a8b0fe674070d2813141f2cf0476be33700e36ed88b0b5d5277d620036db990eed93d815b37a68ae08c722227a4900d544d3a4b93defd3ebc5e2f0b6a078100").unwrap()
    };
    let sign: H224 = H224::from(
        Hash::from_str("01e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4").unwrap(),
    );

    let mint = Some(Multiasset::from((
        control_token_policy,
        control_token_name,
        1,
    )));
    let mint_redeemer = Redeemer {
        tag: RedeemerTag::Mint,
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

    transaction.transaction_body.mint = mint;
    transaction.transaction_body.required_signers = Some(vec![sign]);
    transaction.transaction_witness_set.vkeywitness = Some(vec![vkeywitness]);
    transaction.transaction_witness_set.redeemer = Some(vec![mint_redeemer]);
    transaction.transaction_witness_set.plutus_script = Some(vec![script.clone()]);

    let pallas_tx: PallasTransaction = <_>::from(transaction.clone());
    let cbor_bytes: Vec<u8> = babbage_tx_to_cbor(&pallas_tx);
    let mtx: ConwayMintedTx = conway_minted_tx_from_cbor(&cbor_bytes);

    let redeemers = eval_phase_two(
        &mtx,
        &vec![],
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
fn test_eval_order_resolve() {
    use crate::checks_interface::conway_minted_tx_from_cbor;
    use crate::pallas_codec::utils::MaybeIndefArray::Def;
    use crate::pallas_crypto::hash::Hash;
    use crate::pallas_primitives::conway::{
        Constr, MintedTx as ConwayMintedTx, PlutusData as PallasPlutusData, TransactionInput,
        TransactionOutput,
    };
    use crate::types::{
        compute_plutus_v2_script_hash, Address, AssetClass, AssetName, Datum, ExUnits, Input,
        Multiasset, OrderDatum, Output, PlutusData, PlutusScript, Redeemer, RedeemerTag,
        VKeyWitness, Value,
    };
    use crate::uplc::tx::{eval_phase_two, ResolvedInput, SlotConfig};
    use crate::H224;
    use core::str::FromStr;
    use sp_core::H256;

    let script = PlutusScript(hex::decode("59080c010000323232323232322253232323330063001300737540082a66600c646464646464a66601866e1c005200114a2264646464a666026602c004264646464646464a66602ea66602e60260182a66602e60146eb8c044c064dd5002899b8f00d375c600660326ea80145280a501533301700415333017001100214a0294052819b8848000dd69801180c1baa30023018375400a66e1cc94ccc058c048c05cdd50008a400026eb4c06cc060dd500099299980b1809180b9baa00114c0103d87a8000132330010013756603860326ea8008894ccc06c004530103d87a80001323232533301b3371e0226eb8c07000c4c060cc07cdd4000a5eb804cc014014008dd6980e001180f801180e80099198008009bab30023018375400e44a666034002298103d87a80001323232533301a300d375c60360062602e6603c6e980052f5c026600a00a0046eacc06c008c078008c0700040288c068c06c004cc88c8cc00400400c894ccc068004528099299980c19b8f375c603a00400829444cc00c00c004c074004dd6180c180c980c980c980c980c980c980c980c980a9baa300d301537540226eb8c034c054dd5001180b980c001180b00098091baa332253330123370e900218099baa001132325333017301a0021320025333014300f30153754002264646464a666036603c00426464931804801299980c1809980c9baa003132323232533301f30220021324994ccc070c05cc074dd50008991919192999811981300109924c60200062c6eb4c090004c090008c088004c078dd50008b0b181000098100011bae301e001301a37540062c2c603800260380046034002602c6ea80045858c060004c050dd50008b12999808980618091baa0011323232325333018301b002149858dd7180c800980c8011bae3017001301337540022c600860246ea800458c050004c8cc004004dd6180198089baa30093011375401a44a666026002297ae0132325333012325333013300f301437540022600c6eb8c060c054dd50008a50300c30143754601860286ea80084cc058008cc0100100044cc010010004c05c008c054004dc780291809180998098009bad30103011002375c601e002601e0046eb8c034004c8c94ccc030c03c008400458dd61806800991980080099198008009bab300e300f300f300f300f300b3754600660166ea801c894ccc03400452f5bded8c0264646464a66601c66e3d2201000021003133012337606ea4008dd3000998030030019bab300f003375c601a0046022004601e00244a666018002297ae01323332223233001001003225333012001100313233014374e660286ea4018cc050dd49bae30110013301437506eb4c0480052f5c066006006602c00460280026eb8c02c004dd598060009980180198080011807000918060008a4c26cac26644644a666014646464646464646464a666026a666026601c60286ea80304c8c94ccc060c06c0084cdc78009bae300b301737546016602e6ea805058dd7180c8009bac301830193019301930193019301930193019301537546012602a6ea80284c8c8c8c8c94ccc060cdd79807180d1baa00530153301c30153301c300e301a3754601c60346ea805d2f5c06603898103d87a80004bd7008008a5053330173375e602866036603800666036603800497ae0300d30193754600c60326ea8c034c064dd500b099b89375a600c60326ea8c018c064dd51806980c9baa01600114a06eb4c06cc070004c06c0054ccc050cdc79bae300a301637546014602c6ea8c00cc058dd51805180b1baa013488100132325333019301c0021323301b301c0023301b301c0013301b301c301d0014bd70180e0008b1bac301a001300937566006602c6ea80044c8c94ccc064c0700084c8cc06cc070008cc06cc070004cc06cc070c0740052f5c060380022c6eb0c068004c024cc020dd59801980b1baa001488100325333014300f3015375400226032602c6ea800458c94ccc05c004530103d87a8000130113301830190014bd701bac301830193019301537546012602a6ea80284004528299980919b87375a602e603000690008a99980919b8f004375c601060286ea8c004c050dd5008899b8f002375c600260286ea8c004c050dd50088a5014a04602e60300026eb8c054004c054008dd7180980099192999809180a80108008b1bac3013001300233001375660246026602660266026601e6ea8c00cc03cdd500224410022323300100100322533301300114bd6f7b630099191919299980a19b8f0070021003133018337606ea4008dd3000998030030019bab3015003375c6026004602e004602a0024646600200200444a666022002297ae01323332223233001001003225333017001100313233019374e660326ea4018cc064dd49bae30160013301937506eb4c05c0052f5c066006006603600460320026eb8c040004dd5980880099801801980a8011809800918080008a4c26cac64a66601260080022a66601860166ea8008526161533300930050011533300c300b37540042930b0b18049baa00132533300730023008375400c264646464a66601c6022004264649318030012999805980318061baa003132323232533301230150021324994ccc03cc028c040dd5000899191919299980b180c80109924c601a0062c6eb4c05c004c05c008c054004c044dd50008b0b180980098098011bae3011001300d37540062c2c601e002601e004601a00260126ea80185894ccc01cc008c020dd5000899191919299980718088010a4c2c6eb8c03c004c03c008dd7180680098049baa00116300b300837540086e1d2000370e90011ba5480015cd2ab9d5573caae7d5d02ba157441").unwrap());
    let script_hash = compute_plutus_v2_script_hash(script.clone());

    let token_a_policy = H224::from(
        Hash::from_str("0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005").unwrap(),
    );
    let token_a_name = AssetName::from("tokenA".to_string());
    let token_b_policy = H224::from(
        Hash::from_str("0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005").unwrap(),
    );
    let token_b_name = AssetName::from("tokenB".to_string());
    let token_b_amount: u64 = 2;

    let sender_payment_hash = H224::from(
        Hash::from_str("01e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4").unwrap(),
    );
    let control_token_policy = script_hash;
    let control_token_name = AssetName::from("controlToken".to_string());

    let order_datum = OrderDatum::Ok {
        sender_payment_hash: sender_payment_hash,
        control_token_class: AssetClass {
            policy_id: control_token_policy,
            asset_name: control_token_name.clone(),
        },
        ordered_class: AssetClass {
            policy_id: token_b_policy,
            asset_name: token_b_name.clone(),
        },
        ordered_amount: token_b_amount,
    };

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
    let resolved_inputs = vec![
        Output {
            address: Address(hex::decode("70".to_owned() + &hex::encode(script_hash)).unwrap()),
            value: Value::from((314, token_a_policy, token_a_name, 1)),
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
        value: Value::from((10, token_b_policy, token_b_name, 2)),
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
            fields: Def([PallasPlutusData::Constr(Constr {
                tag: 122,
                any_constructor: None,
                fields: Def([].to_vec()),
            })]
            .to_vec()),
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

    let mint = Some(Multiasset::from((
        control_token_policy,
        control_token_name,
        -1,
    )));
    let burn_redeemer = Redeemer {
        tag: RedeemerTag::Mint,
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

    transaction.transaction_body.mint = mint;
    transaction.transaction_body.required_signers = Some(vec![sign]);
    transaction.transaction_witness_set.vkeywitness = Some(vec![vkeywitness]);
    transaction.transaction_witness_set.redeemer = Some(vec![burn_redeemer, resolve_redeemer]);
    transaction.transaction_witness_set.plutus_script = Some(vec![script]);

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
    assert_eq!(redeemers.len(), 2);
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
        compute_plutus_v2_script_hash, Address, AssetClass, AssetName, Datum, ExUnits, Input,
        Multiasset, OrderDatum, Output, PlutusData, PlutusScript, Redeemer, RedeemerTag,
        VKeyWitness, Value,
    };
    use crate::uplc::tx::{eval_phase_two, ResolvedInput, SlotConfig};
    use crate::H224;
    use core::str::FromStr;
    use sp_core::H256;

    let script = PlutusScript(hex::decode("59080c010000323232323232322253232323330063001300737540082a66600c646464646464a66601866e1c005200114a2264646464a666026602c004264646464646464a66602ea66602e60260182a66602e60146eb8c044c064dd5002899b8f00d375c600660326ea80145280a501533301700415333017001100214a0294052819b8848000dd69801180c1baa30023018375400a66e1cc94ccc058c048c05cdd50008a400026eb4c06cc060dd500099299980b1809180b9baa00114c0103d87a8000132330010013756603860326ea8008894ccc06c004530103d87a80001323232533301b3371e0226eb8c07000c4c060cc07cdd4000a5eb804cc014014008dd6980e001180f801180e80099198008009bab30023018375400e44a666034002298103d87a80001323232533301a300d375c60360062602e6603c6e980052f5c026600a00a0046eacc06c008c078008c0700040288c068c06c004cc88c8cc00400400c894ccc068004528099299980c19b8f375c603a00400829444cc00c00c004c074004dd6180c180c980c980c980c980c980c980c980c980a9baa300d301537540226eb8c034c054dd5001180b980c001180b00098091baa332253330123370e900218099baa001132325333017301a0021320025333014300f30153754002264646464a666036603c00426464931804801299980c1809980c9baa003132323232533301f30220021324994ccc070c05cc074dd50008991919192999811981300109924c60200062c6eb4c090004c090008c088004c078dd50008b0b181000098100011bae301e001301a37540062c2c603800260380046034002602c6ea80045858c060004c050dd50008b12999808980618091baa0011323232325333018301b002149858dd7180c800980c8011bae3017001301337540022c600860246ea800458c050004c8cc004004dd6180198089baa30093011375401a44a666026002297ae0132325333012325333013300f301437540022600c6eb8c060c054dd50008a50300c30143754601860286ea80084cc058008cc0100100044cc010010004c05c008c054004dc780291809180998098009bad30103011002375c601e002601e0046eb8c034004c8c94ccc030c03c008400458dd61806800991980080099198008009bab300e300f300f300f300f300b3754600660166ea801c894ccc03400452f5bded8c0264646464a66601c66e3d2201000021003133012337606ea4008dd3000998030030019bab300f003375c601a0046022004601e00244a666018002297ae01323332223233001001003225333012001100313233014374e660286ea4018cc050dd49bae30110013301437506eb4c0480052f5c066006006602c00460280026eb8c02c004dd598060009980180198080011807000918060008a4c26cac26644644a666014646464646464646464a666026a666026601c60286ea80304c8c94ccc060c06c0084cdc78009bae300b301737546016602e6ea805058dd7180c8009bac301830193019301930193019301930193019301537546012602a6ea80284c8c8c8c8c94ccc060cdd79807180d1baa00530153301c30153301c300e301a3754601c60346ea805d2f5c06603898103d87a80004bd7008008a5053330173375e602866036603800666036603800497ae0300d30193754600c60326ea8c034c064dd500b099b89375a600c60326ea8c018c064dd51806980c9baa01600114a06eb4c06cc070004c06c0054ccc050cdc79bae300a301637546014602c6ea8c00cc058dd51805180b1baa013488100132325333019301c0021323301b301c0023301b301c0013301b301c301d0014bd70180e0008b1bac301a001300937566006602c6ea80044c8c94ccc064c0700084c8cc06cc070008cc06cc070004cc06cc070c0740052f5c060380022c6eb0c068004c024cc020dd59801980b1baa001488100325333014300f3015375400226032602c6ea800458c94ccc05c004530103d87a8000130113301830190014bd701bac301830193019301537546012602a6ea80284004528299980919b87375a602e603000690008a99980919b8f004375c601060286ea8c004c050dd5008899b8f002375c600260286ea8c004c050dd50088a5014a04602e60300026eb8c054004c054008dd7180980099192999809180a80108008b1bac3013001300233001375660246026602660266026601e6ea8c00cc03cdd500224410022323300100100322533301300114bd6f7b630099191919299980a19b8f0070021003133018337606ea4008dd3000998030030019bab3015003375c6026004602e004602a0024646600200200444a666022002297ae01323332223233001001003225333017001100313233019374e660326ea4018cc064dd49bae30160013301937506eb4c05c0052f5c066006006603600460320026eb8c040004dd5980880099801801980a8011809800918080008a4c26cac64a66601260080022a66601860166ea8008526161533300930050011533300c300b37540042930b0b18049baa00132533300730023008375400c264646464a66601c6022004264649318030012999805980318061baa003132323232533301230150021324994ccc03cc028c040dd5000899191919299980b180c80109924c601a0062c6eb4c05c004c05c008c054004c044dd50008b0b180980098098011bae3011001300d37540062c2c601e002601e004601a00260126ea80185894ccc01cc008c020dd5000899191919299980718088010a4c2c6eb8c03c004c03c008dd7180680098049baa00116300b300837540086e1d2000370e90011ba5480015cd2ab9d5573caae7d5d02ba157441").unwrap());
    let script_hash = compute_plutus_v2_script_hash(script.clone());

    let token_b_policy = H224::from(
        Hash::from_str("0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005").unwrap(),
    );
    let token_b_name = AssetName::from("tokenB".to_string());
    let token_a_policy = token_b_policy;
    let token_a_name = AssetName::from("tokenA".to_string());
    let token_b_amount: u64 = 2;

    let sender_payment_hash = H224::from(
        Hash::from_str("5b6de1be218ebb35fc08b2983e3a1d72aec969c8d2a6301212e2ea9a").unwrap(),
    );
    let control_token_policy = script_hash;
    let control_token_name = AssetName::from("controlToken".to_string());

    let order_datum = OrderDatum::Ok {
        sender_payment_hash: sender_payment_hash,
        control_token_class: AssetClass {
            policy_id: control_token_policy,
            asset_name: control_token_name.clone(),
        },
        ordered_class: AssetClass {
            policy_id: token_b_policy,
            asset_name: token_b_name,
        },
        ordered_amount: token_b_amount,
    };

    let inputs = vec![Input {
        tx_hash: H256::from_slice(
            hex::decode("88832d2909740fdedac6b39348303b62a2d3d7f6d25a79c349768fe113dab451")
                .unwrap()
                .as_slice(),
        ),
        index: 0,
    }];
    let resolved_inputs = vec![Output {
        address: Address(hex::decode("70".to_owned() + &hex::encode(script_hash)).unwrap()),
        value: Value::from((314, token_a_policy, token_a_name, 1))
            + Value::from((control_token_policy, control_token_name.clone(), 1)),
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

    let cancel_redeemer = Redeemer {
        tag: RedeemerTag::Spend,
        index: 0,
        data: PlutusData::from(PallasPlutusData::Constr(Constr {
            tag: 122,
            any_constructor: None,
            fields: Def([PallasPlutusData::Constr(Constr {
                tag: 121,
                any_constructor: None,
                fields: Def([].to_vec()),
            })]
            .to_vec()),
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

    let burn_redeemer = Redeemer {
        tag: RedeemerTag::Mint,
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
    let mint = Some(Multiasset::from((
        control_token_policy,
        control_token_name,
        -1,
    )));

    transaction.transaction_body.mint = mint;
    transaction.transaction_body.required_signers = Some(vec![sender_payment_hash]);
    let vkeywitness = VKeyWitness {
        vkey: hex::decode("F6E9814CE6626EB532372B1740127E153C28D643A9384F51B1B0229AEDA43717").unwrap(),
        signature: hex::decode("A4ACDA77397F7A80B21FA17AE95FCC99C255069B8135897BA8A7A5EC0E829DBA91171FBF794C1A5E6249263B04075C659BDEBA1B1E10E38F734539626BFF6905").unwrap()
    };
    transaction.transaction_witness_set.vkeywitness = Some(vec![vkeywitness]);
    transaction.transaction_witness_set.redeemer = Some(vec![cancel_redeemer, burn_redeemer]);
    transaction.transaction_witness_set.plutus_script = Some(vec![script]);

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
    assert_eq!(redeemers.len(), 2);
}

#[test]
fn test_one_shot_mp() {
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
    use crate::pallas_primitives::Fragment;
    use crate::types::{
        compute_plutus_v2_script_hash, Address, AssetName, ExUnits, Input, Multiasset, Output,
        PlutusData, PlutusScript, Redeemer, RedeemerTag, Value,
    };
    use crate::uplc::tx::{apply_params_to_script, eval_phase_two, ResolvedInput, SlotConfig};
    use crate::H224;
    use core::str::FromStr;
    use sp_core::H256;

    let parameterized_script_hex = "59026e01010032323232323232323222253330053232323232533300a3370e900018061baa004132533300f001153300c00a161325333010301300213232533300e533300e3370e004900108008a5014a2266e1c0092001323300100100622533301300114a0264a66602066ebcc058c04cdd5180b0010070a511330030030013016001375a601e0022a6601a0162c602200264a66601666e1d2002300d3754002297adef6c60137566022601c6ea8004c8c8cc004004c8cc004004010894ccc04800452f5bded8c0264646464a66602466e45220100002153330123371e91010000210031005133017337606ea4008dd3000998030030019bab3014003375c6024004602c004602800244a666022002298103d87a800013232323253330113372200e0042a66602266e3c01c0084cdd2a40006602c6e980052f5c02980103d87a8000133006006003375660260066eb8c044008c054008c04c004dd7180818069baa004153300b49120657870656374204d696e7428706f6c6963795f696429203d20707572706f736500163756601e60206020602060200046eb0c038004c028dd518068011806180680098041baa001149854cc0192411856616c696461746f722072657475726e65642066616c7365001365649188657870656374205b50616972285f2c207175616e74697479295d203d0a2020202020206d696e740a20202020202020207c3e2076616c75652e66726f6d5f6d696e7465645f76616c75650a20202020202020207c3e2076616c75652e746f6b656e7328706f6c6963795f6964290a20202020202020207c3e20646963742e746f5f70616972732829005734ae7155ceaab9e5573eae815d0aba21";
    let input_tx_id = "25667b8e0fbf599ee2d640a4ab74accdb07a4c4b99b3a62f27e8e865f7ef5774";
    let input_index = 0;

    let input = Input {
        tx_hash: H256::from_slice(hex::decode(input_tx_id).unwrap().as_slice()),
        index: input_index,
    };

    let utxo_ref_data = PallasPlutusData::Array(Indef(
        [PallasPlutusData::Constr(Constr {
            tag: 121,
            any_constructor: None,
            fields: Indef(
                [
                    PallasPlutusData::Constr(Constr {
                        tag: 121,
                        any_constructor: None,
                        fields: Indef(
                            [PallasPlutusData::BoundedBytes(BoundedBytes(
                                hex::decode(input_tx_id).unwrap(),
                            ))]
                            .to_vec(),
                        ),
                    }),
                    PallasPlutusData::BigInt(BigInt::Int(Int(minicbor::data::Int::from(
                        input_index,
                    )))),
                ]
                .to_vec(),
            ),
        })]
        .to_vec(),
    ));

    let script = PlutusScript(
        apply_params_to_script(
            utxo_ref_data.encode_fragment().unwrap().as_slice(),
            hex::decode(parameterized_script_hex).unwrap().as_slice(),
        )
        .unwrap(),
    );
    let policy = compute_plutus_v2_script_hash(script.clone());

    let sender_payment_hash = H224::from(
        Hash::from_str("5b6de1be218ebb35fc08b2983e3a1d72aec969c8d2a6301212e2ea9a").unwrap(),
    );

    let inputs = vec![input];
    let resolved_inputs = vec![Output {
        address: Address(hex::decode("70".to_owned() + &hex::encode(sender_payment_hash)).unwrap()),
        value: Value::Coin(10),
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

    let mut transaction = Transaction::from((Vec::new(), Vec::new()));
    for input in inputs {
        transaction.transaction_body.inputs.push(input.clone());
    }

    let mint_redeemer = Redeemer {
        tag: RedeemerTag::Mint,
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
    let mint = Some(Multiasset::from((
        policy,
        AssetName::from("oneShot".to_string()),
        1,
    )));

    transaction.transaction_body.mint = mint;
    transaction.transaction_witness_set.redeemer = Some(vec![mint_redeemer]);
    transaction.transaction_witness_set.plutus_script = Some(vec![script]);

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
fn test_aiken_hello_world() {
    use crate::checks_interface::conway_minted_tx_from_cbor;
    use crate::pallas_codec::utils::MaybeIndefArray::Indef;
    use crate::pallas_crypto::hash::Hash;
    use crate::pallas_primitives::conway::{
        BoundedBytes, Constr, MintedTx as ConwayMintedTx, PlutusData as PallasPlutusData,
        TransactionInput, TransactionOutput,
    };
    use crate::types::{
        compute_plutus_v2_script_hash, Address, Datum, ExUnits, Input, Output, PlutusData,
        PlutusScript, Redeemer, RedeemerTag, VKeyWitness, Value,
    };
    use crate::uplc::tx::{eval_phase_two, ResolvedInput, SlotConfig};
    use crate::H224;
    use core::str::FromStr;
    use sp_core::H256;

    let script = PlutusScript(hex::decode("58f2010000323232323232323222232325333008323232533300b002100114a06644646600200200644a66602200229404c8c94ccc040cdc78010028a511330040040013014002375c60240026eb0c038c03cc03cc03cc03cc03cc03cc03cc03cc020c008c020014dd71801180400399b8f375c6002600e00a91010d48656c6c6f2c20576f726c6421002300d00114984d958c94ccc020cdc3a400000226464a66601a601e0042930b1bae300d00130060041630060033253330073370e900000089919299980618070010a4c2c6eb8c030004c01401058c01400c8c014dd5000918019baa0015734aae7555cf2ab9f5742ae881").unwrap());
    let script_hash = compute_plutus_v2_script_hash(script.clone());

    let owner = H224::from(
        Hash::from_str("5b6de1be218ebb35fc08b2983e3a1d72aec969c8d2a6301212e2ea9a").unwrap(),
    );

    let datum = PallasPlutusData::Constr(Constr {
        tag: 121,
        any_constructor: None,
        fields: Indef(
            [PallasPlutusData::BoundedBytes(BoundedBytes(
                owner.0.to_vec(),
            ))]
            .to_vec(),
        ),
    });

    let inputs = vec![Input {
        tx_hash: H256::from_slice(
            hex::decode("88832d2909740fdedac6b39348303b62a2d3d7f6d25a79c349768fe113dab451")
                .unwrap()
                .as_slice(),
        ),
        index: 0,
    }];
    let resolved_inputs = vec![Output {
        address: Address(hex::decode("70".to_owned() + &hex::encode(script_hash)).unwrap()),
        value: Value::Coin(10),
        datum_option: Some(Datum(PlutusData::from(datum.clone()).0)),
    }];

    let pallas_inputs = inputs
        .iter()
        .map(|i| TransactionInput::from(i.clone()))
        .collect::<Vec<_>>();
    let pallas_resolved_inputs = resolved_inputs
        .iter()
        .map(|ri| TransactionOutput::from(ri.clone()))
        .collect::<Vec<_>>();

    let redeemer = Redeemer {
        tag: RedeemerTag::Spend,
        index: 0,
        data: PlutusData::from(PallasPlutusData::Constr(Constr {
            tag: 121,
            any_constructor: None,
            fields: Indef(
                [PallasPlutusData::BoundedBytes(BoundedBytes(
                    "Hello, World!".as_bytes().to_vec(),
                ))]
                .to_vec(),
            ),
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

    transaction.transaction_body.required_signers = Some(vec![owner]);
    let vkeywitness = VKeyWitness {
        vkey: hex::decode("F6E9814CE6626EB532372B1740127E153C28D643A9384F51B1B0229AEDA43717").unwrap(),
        signature: hex::decode("A4ACDA77397F7A80B21FA17AE95FCC99C255069B8135897BA8A7A5EC0E829DBA91171FBF794C1A5E6249263B04075C659BDEBA1B1E10E38F734539626BFF6905").unwrap()
    };
    transaction.transaction_witness_set.vkeywitness = Some(vec![vkeywitness]);
    transaction.transaction_witness_set.redeemer = Some(vec![redeemer]);
    transaction.transaction_witness_set.plutus_script = Some(vec![script]);

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
