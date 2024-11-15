//! # Executive Module
//!
//! The executive is the main orchestrator for the entire runtime.
//! It has functions that implement the Core, BlockBuilder, and TxPool runtime APIs.
//!
//! It does all the reusable verification of UTXO transactions.

use crate::{
    ensure,
    types::{
        Block, BlockNumber, DispatchResult, Header, Input, Transaction,
        UTxOError,
    },
    utxo_set::TransparentUtxoSet,
    EXTRINSIC_KEY,
    HEADER_KEY,
    HEIGHT_KEY,
    LOG_TARGET,
    checks_interface::{
        mk_utxo_for_babbage_tx,
        babbage_tx_to_cbor,
        babbage_minted_tx_from_cbor,
        check_min_coin,
    },
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
use alloc::{
    collections::btree_set::BTreeSet,
    vec::Vec,
    string::String,
};
use crate::pallas_applying::{
    UTxOs,
    babbage::{
        check_ins_not_empty,
        // check_all_ins_in_utxos,
        check_preservation_of_value,
        check_witness_set,
    },
    utils::BabbageError::*,
};
use crate::pallas_primitives::{
    babbage::{
        Tx as PallasTransaction, MintedScriptRef, MintedDatumOption, MintedTx,
        Value as PallasValue, MintedTransactionBody,
    },
    conway::{CostMdls, TransactionInput, TransactionOutput},
    Fragment
};
use crate::pallas_codec::utils::CborWrap;
use crate::pallas_traverse::{Era, MultiEraTx};
use crate::uplc::{machine::cost_model::ExBudget, tx::{eval_phase_two, ResolvedInput, SlotConfig}};

type OutputInfoList<'a> =  Vec<(
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
    fn pool_checks(
        mtx: &MintedTx,
        _utxos: &UTxOs,
    ) -> DispatchResult {

        check_ins_not_empty(&mtx.transaction_body.clone())?;
        Ok(())
    }

    /// Checks performed to a transaction with all its requirements satisfied
    /// to be included in a block.
    fn ledger_checks(
        mtx: &MintedTx,
        utxos: &UTxOs,
    ) -> DispatchResult {
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
            let input_set: BTreeSet<_> = transaction.transaction_body.inputs.iter().map(|o| o.encode()).collect();
            ensure!(
                input_set.len() == transaction.transaction_body.inputs.len(),
                UTxOError::Babbage(DuplicateInput)
            );
        }

        let mut tx_outs_info: OutputInfoList = Vec::new();
        
        // Add present inputs to a list to be used to produce the local UTxO set.
        // Keep track of any missing inputs for use in the tagged transaction pool
        let mut missing_inputs = Vec::new();
        for input in transaction.transaction_body.inputs.iter() {
            if let Some(u) = TransparentUtxoSet::peek_utxo(&input) {
                tx_outs_info.push((
                    hex::encode(u.address.0.as_slice()),
                    PallasValue::from(u.value),
                    None,
                    None,
                ));
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
            return Ok((tx_outs_info, ValidTransaction {
                requires: missing_inputs,
                provides,
                priority: 0,
                longevity: TransactionLongevity::MAX,
                propagate: true,
            }));
        }

        // Return the valid transaction
        Ok((tx_outs_info, ValidTransaction {
            requires: Vec::new(),
            provides,
            priority: 0,
            longevity: TransactionLongevity::MAX,
            propagate: true,
        }))
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

        let r = Self::validate_griffin_transaction(&tx).map_err(|e| {
                    log::warn!(
                        target: LOG_TARGET,
                        "Griffin Transaction did not validate (in the pool): {:?}",
                        e,
                    );
                    TransactionValidityError::Invalid(e.into())
                }).map(|x| x.1);

        debug!(target: LOG_TARGET, "Validation result: {:?}", r);

        r
    }
}
    
#[test]
fn test_eval_0() {
    /*

    PlutusV2

    {-# INLINEABLE mintTestValidator #-}
    mintTestValidator :: () -> Api.ScriptContext -> Bool
    mintTestValidator _ ctx = Api.txInfoFee txInfo == Api.txInfoFee txInfo && (case Api.txInfoSignatories txInfo of [] -> True)

      where
        txInfo :: Api.TxInfo
        txInfo = Api.scriptContextTxInfo ctx */

    let tx_bytes = hex::decode("84a80081825820975c17a4fed0051be622328efa548e206657d2b65a19224bf6ff8132571e6a5002018282581d60b6c8794e9a7a26599440a4d0fd79cd07644d15917ff13694f1f67235821a000f41f0a1581cc4f241450001af08f3ddbaf9335db79883cbcd81071b8e3508de3055a1400a82581d60b6c8794e9a7a26599440a4d0fd79cd07644d15917ff13694f1f672351a0084192f021a00053b6109a1581cc4f241450001af08f3ddbaf9335db79883cbcd81071b8e3508de3055a1400a0b5820b4f96b0acec8beff2adededa8ba317bcac92174f0f65ccefe569b9a6aac7375a0d818258206c732139de33e916342707de2aebef2252c781640326ff37b86ec99d97f1ba8d011082581d60b6c8794e9a7a26599440a4d0fd79cd07644d15917ff13694f1f672351b00000001af0cdfa2111a0007d912a3008182582031ae74f8058527afb305d7495b10a99422d9337fc199e1f28044f2c477a0f9465840b8b97b7c3b4e19ecfc2fcd9884ee53a35887ee6e4d36901b9ecbac3fe032d7e8a4358305afa573a86396e378255651ed03501906e9def450e588d4bb36f42a050581840100d87980821a000b68081a0cf3a5bf06815909b25909af010000323322323232323232323232323232323232323232332232323232323232323233223232223232533533223233025323233355300f1200135028502623500122333553012120013502b50292350012233350012330314800000488cc0c80080048cc0c400520000013355300e1200123500122335501c0023335001233553012120012350012233550200023550140010012233355500f0150020012335530121200123500122335502000235501300100133355500a01000200130105002300f5001533532350012222222222220045001102a2216135001220023333573466e1cd55ce9baa0044800080808c98c8080cd5ce01081000f1999ab9a3370e6aae7540092000233221233001003002323232323232323232323232323333573466e1cd55cea8062400046666666666664444444444442466666666666600201a01801601401201000e00c00a00800600466a03803a6ae854030cd4070074d5d0a80599a80e00f1aba1500a3335502075ca03e6ae854024ccd54081d7280f9aba1500833501c02835742a00e666aa040052eb4d5d0a8031919191999ab9a3370e6aae75400920002332212330010030023232323333573466e1cd55cea8012400046644246600200600466a066eb4d5d0a801181a1aba135744a004464c6406c66ae700dc0d80d04d55cf280089baa00135742a0046464646666ae68cdc39aab9d5002480008cc8848cc00400c008cd40cdd69aba150023034357426ae8940088c98c80d8cd5ce01b81b01a09aab9e5001137540026ae84d5d1280111931901919ab9c033032030135573ca00226ea8004d5d0a80299a80e3ae35742a008666aa04004a40026ae85400cccd54081d710009aba150023027357426ae8940088c98c80b8cd5ce01781701609aba25001135744a00226ae8940044d5d1280089aba25001135744a00226ae8940044d5d1280089aba25001135744a00226aae7940044dd50009aba150023017357426ae8940088c98c8080cd5ce01081000f080f89931900f99ab9c4901035054350001f135573ca00226ea8004444888ccd54c010480054040cd54c01c480048d400488cd54054008d54024004ccd54c0104800488d4008894cd4ccd54c03048004c8cd409c88ccd400c88008008004d40048800448cc004894cd400840b040040a48d400488cc028008014018400c4cd405001000d4044004cd54c01c480048d400488c8cd5405800cc004014c8004d540a4894cd40044d5402800c884d4008894cd4cc03000802044888cc0080280104c01800c008c8004d5408888448894cd40044008884cc014008ccd54c01c480040140100044484888c00c0104484888c004010c8004d5407c8844894cd400454038884cd403cc010008cd54c01848004010004c8004d5407888448894cd40044d400c88004884ccd401488008c010008ccd54c01c4800401401000488ccd5cd19b8f00200101e01d2350012222222222220091232230023758002640026aa038446666aae7c004940288cd4024c010d5d080118019aba2002015232323333573466e1cd55cea80124000466442466002006004601a6ae854008c014d5d09aba2500223263201533573802c02a02626aae7940044dd50009191919191999ab9a3370e6aae75401120002333322221233330010050040030023232323333573466e1cd55cea80124000466442466002006004602c6ae854008cd4040054d5d09aba2500223263201a33573803603403026aae7940044dd50009aba150043335500875ca00e6ae85400cc8c8c8cccd5cd19b875001480108c84888c008010d5d09aab9e500323333573466e1d4009200223212223001004375c6ae84d55cf280211999ab9a3370ea00690001091100191931900e19ab9c01d01c01a019018135573aa00226ea8004d5d0a80119a8063ae357426ae8940088c98c8058cd5ce00b80b00a09aba25001135744a00226aae7940044dd5000899aa800bae75a224464460046eac004c8004d5406488c8cccd55cf80112804119a80399aa80498031aab9d5002300535573ca00460086ae8800c04c4d5d08008891001091091198008020018891091980080180109119191999ab9a3370ea0029000119091180100198029aba135573ca00646666ae68cdc3a801240044244002464c6402066ae700440400380344d55cea80089baa001232323333573466e1d400520062321222230040053007357426aae79400c8cccd5cd19b875002480108c848888c008014c024d5d09aab9e500423333573466e1d400d20022321222230010053007357426aae7940148cccd5cd19b875004480008c848888c00c014dd71aba135573ca00c464c6402066ae7004404003803403002c4d55cea80089baa001232323333573466e1cd55cea80124000466442466002006004600a6ae854008dd69aba135744a004464c6401866ae700340300284d55cf280089baa0012323333573466e1cd55cea800a400046eb8d5d09aab9e500223263200a33573801601401026ea80048c8c8c8c8c8cccd5cd19b8750014803084888888800c8cccd5cd19b875002480288488888880108cccd5cd19b875003480208cc8848888888cc004024020dd71aba15005375a6ae84d5d1280291999ab9a3370ea00890031199109111111198010048041bae35742a00e6eb8d5d09aba2500723333573466e1d40152004233221222222233006009008300c35742a0126eb8d5d09aba2500923333573466e1d40192002232122222223007008300d357426aae79402c8cccd5cd19b875007480008c848888888c014020c038d5d09aab9e500c23263201333573802802602202001e01c01a01801626aae7540104d55cf280189aab9e5002135573ca00226ea80048c8c8c8c8cccd5cd19b875001480088ccc888488ccc00401401000cdd69aba15004375a6ae85400cdd69aba135744a00646666ae68cdc3a80124000464244600400660106ae84d55cf280311931900619ab9c00d00c00a009135573aa00626ae8940044d55cf280089baa001232323333573466e1d400520022321223001003375c6ae84d55cf280191999ab9a3370ea004900011909118010019bae357426aae7940108c98c8024cd5ce00500480380309aab9d50011375400224464646666ae68cdc3a800a40084244400246666ae68cdc3a8012400446424446006008600c6ae84d55cf280211999ab9a3370ea00690001091100111931900519ab9c00b00a008007006135573aa00226ea80048c8cccd5cd19b8750014800880348cccd5cd19b8750024800080348c98c8018cd5ce00380300200189aab9d37540029309000a4810350543100112330010020072253350021001100612335002223335003220020020013500122001122123300100300222333573466e1c00800401000c488008488004448c8c00400488cc00cc008008005f5f6").unwrap();

    let raw_inputs = hex::decode("84825820b16778c9cf065d9efeefe37ec269b4fc5107ecdbd0dd6bf3274b224165c2edd9008258206c732139de33e916342707de2aebef2252c781640326ff37b86ec99d97f1ba8d01825820975c17a4fed0051be622328efa548e206657d2b65a19224bf6ff8132571e6a500282582018f86700660fc88d0370a8f95ea58f75507e6b27a18a17925ad3b1777eb0d77600").unwrap();
    let raw_outputs = hex::decode("8482581d60b6c8794e9a7a26599440a4d0fd79cd07644d15917ff13694f1f67235821a000f8548a1581c15be994a64bdb79dde7fe080d8e7ff81b33a9e4860e9ee0d857a8e85a144576177610182581d60b6c8794e9a7a26599440a4d0fd79cd07644d15917ff13694f1f672351b00000001af14b8b482581d60b6c8794e9a7a26599440a4d0fd79cd07644d15917ff13694f1f672351a0098968082581d60b6c8794e9a7a26599440a4d0fd79cd07644d15917ff13694f1f672351a00acd8c6").unwrap();

    let inputs = Vec::<TransactionInput>::decode_fragment(&raw_inputs).unwrap();
    let outputs = Vec::<TransactionOutput>::decode_fragment(&raw_outputs).unwrap();

    let utxos: Vec<ResolvedInput> = inputs
        .iter()
        .zip(outputs.iter())
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

    let costs: Vec<i64> = vec![
        205665,
        812,
        1,
        1,
        1000,
        571,
        0,
        1,
        1000,
        24177,
        4,
        1,
        1000,
        32,
        117366,
        10475,
        4,
        23000,
        100,
        23000,
        100,
        23000,
        100,
        23000,
        100,
        23000,
        100,
        23000,
        100,
        100,
        100,
        23000,
        100,
        19537,
        32,
        175354,
        32,
        46417,
        4,
        221973,
        511,
        0,
        1,
        89141,
        32,
        497525,
        14068,
        4,
        2,
        196500,
        453240,
        220,
        0,
        1,
        1,
        1000,
        28662,
        4,
        2,
        245000,
        216773,
        62,
        1,
        1060367,
        12586,
        1,
        208512,
        421,
        1,
        187000,
        1000,
        52998,
        1,
        80436,
        32,
        43249,
        32,
        1000,
        32,
        80556,
        1,
        57667,
        4,
        1000,
        10,
        197145,
        156,
        1,
        197145,
        156,
        1,
        204924,
        473,
        1,
        208896,
        511,
        1,
        52467,
        32,
        64832,
        32,
        65493,
        32,
        22558,
        32,
        16563,
        32,
        76511,
        32,
        196500,
        453240,
        220,
        0,
        1,
        1,
        69522,
        11687,
        0,
        1,
        60091,
        32,
        196500,
        453240,
        220,
        0,
        1,
        1,
        196500,
        453240,
        220,
        0,
        1,
        1,
        1159724,
        392670,
        0,
        2,
        806990,
        30482,
        4,
        1927926,
        82523,
        4,
        265318,
        0,
        4,
        0,
        85931,
        32,
        205665,
        812,
        1,
        1,
        41182,
        32,
        212342,
        32,
        31220,
        32,
        32696,
        32,
        43357,
        32,
        32247,
        32,
        38314,
        32,
        20000000000,
        20000000000,
        9462713,
        1021,
        10,
        20000000000,
        0,
        20000000000,
    ];

    let cost_mdl = CostMdls {
        plutus_v1: None,
        plutus_v2: Some(costs),
        plutus_v3: None,
    };

    let initial_budget = ExBudget {
        cpu: 10000000000,
        mem: 14000000,
    };

    let multi_era_tx = MultiEraTx::decode_for_era(Era::Conway, &tx_bytes)
        .or_else(|_| MultiEraTx::decode_for_era(Era::Babbage, &tx_bytes))
        .or_else(|_| MultiEraTx::decode_for_era(Era::Alonzo, &tx_bytes))
        .unwrap();
    match multi_era_tx {
        MultiEraTx::Conway(tx) => {
            let redeemers = eval_phase_two(
                &tx,
                &utxos,
                Some(&cost_mdl),
                Some(&initial_budget),
                &slot_config,
                false,
                |_| (),
            )
            .unwrap();

            assert_eq!(redeemers.len(), 1);

            let total_budget_used: Vec<ExBudget> = redeemers
                .iter()
                .map(|curr| ExBudget {
                    mem: curr.ex_units.mem as i64,
                    cpu: curr.ex_units.steps as i64,
                })
                .collect();

            println!("{total_budget_used:?}");

            // N scripts return an N length vector of ExBudgets
            let expected_budgets: Vec<ExBudget> = vec![ExBudget {
                mem: 747528,
                cpu: 217294271,
            }];

            assert_eq!(total_budget_used, expected_budgets);
        }
        _ => unreachable!(),
    };
}
