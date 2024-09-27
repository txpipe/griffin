//! # Executive Module
//!
//! The executive is the main orchestrator for the entire runtime.
//! It has functions that implement the Core, BlockBuilder, and TxPool runtime APIs.
//!
//! It does all the reusable verification of UTXO transactions.

use crate::{
    ensure,
    types::{Block, BlockNumber, DispatchResult, Header, OutputRef, Transaction, UtxoError},
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

/// The executive. Each runtime is encouraged to make a type alias called `Executive` that fills
/// in the proper generic types.
pub struct Executive;

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

        // There must be at least one input
        ensure!(!transaction.inputs.is_empty(), UtxoError::NoInputs);

        // Make sure there are no duplicate inputs
        {
            let input_set: BTreeSet<_> = transaction.inputs.iter().map(|o| o.encode()).collect();
            ensure!(
                input_set.len() == transaction.inputs.len(),
                UtxoError::DuplicateInput
            );
        }

        // Keep track of any missing inputs for use in the tagged transaction pool
        let mut missing_inputs = Vec::new();
        for input in transaction.inputs.iter() {
            if None == TransparentUtxoSet::peek_utxo(&input.output_ref) {
                missing_inputs.push(input.output_ref.clone().encode());
            }
        }

        // Make sure no outputs already exist in storage
        let tx_hash = BlakeTwo256::hash_of(&transaction.encode());
        for index in 0..transaction.outputs.len() {
            let output_ref = OutputRef {
                tx_hash,
                index: index as u32,
            };

            debug!(
                target: LOG_TARGET,
                "Checking for pre-existing output {:?}", output_ref
            );

            ensure!(
                TransparentUtxoSet::peek_utxo(&output_ref).is_none(),
                UtxoError::PreExistingOutput
            );
        }

        // Calculate the tx-pool tags provided by this transaction, which
        // are just the encoded OutputRefs
        let provides = (0..transaction.outputs.len())
            .map(|i| {
                let output_ref = OutputRef {
                    tx_hash,
                    index: i as u32,
                };
                output_ref.encode()
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
        for input in &transaction.inputs {
            TransparentUtxoSet::consume_utxo(&input.output_ref);
        }

        debug!(
            target: LOG_TARGET,
            "Transaction before updating storage {:?}", transaction
        );
        // Write the newly created utxos
        for (index, output) in transaction.outputs.iter().enumerate() {
            let output_ref = OutputRef {
                tx_hash: BlakeTwo256::hash_of(&transaction.encode()),
                index: index as u32,
            };
            TransparentUtxoSet::store_utxo(output_ref, output);
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


#[cfg(test)]
mod tests {
    use sp_core::H256;
    use sp_io::TestExternalities;
    use sp_runtime::{transaction_validity::ValidTransactionBuilder};

    use crate::{
        types::{Block, Coin, Header, Input, Output, Transaction},
    };

    use super::*;

    /// Construct a mock OutputRef from a transaction number and index in that transaction.
    ///
    /// When setting up tests, it is often useful to have some Utxos in the storage
    /// before the test begins. There are no real transactions before the test, so there
    /// are also no real OutputRefs. This function constructs an OutputRef that can be
    /// used in the test from a "transaction number" (a simple u32) and an output index in
    /// that transaction (also a u32).
    fn mock_output_ref(tx_num: u32, index: u32) -> OutputRef {
        OutputRef {
            tx_hash: H256::from_low_u64_le(tx_num as u64),
            index,
        }
    }

    /// Construct a mock owner from a u32.
    fn mock_owner(owner_num: u32) -> H256 {
        H256::from_low_u64_le(owner_num as u64)
    }

    /// Builder pattern for test transactions.
    #[derive(Default)]
    struct TestTransactionBuilder {
        inputs: Vec<Input>,
        outputs: Vec<Output>,
    }

    impl TestTransactionBuilder {
        fn with_input(mut self, input: Input) -> Self {
            self.inputs.push(input);
            self
        }

        fn with_output(mut self, output: Output) -> Self {
            self.outputs.push(output);
            self
        }

        fn build(self) -> Transaction {
            Transaction {
                inputs: self.inputs,
                outputs: self.outputs,
            }
        }
    }

    /// Builds test externalities using a minimal builder pattern.
    #[derive(Default)]
    struct ExternalityBuilder {
        utxos: Vec<(OutputRef, Output)>,
        pre_header: Option<Header>,
        noted_extrinsics: Vec<Vec<u8>>,
    }

    impl ExternalityBuilder {
        /// Add the given Utxo to the storage.
        ///
        /// There are no real transactions to calculate OutputRefs so instead we
        /// provide an output ref as a parameter. See the function `mock_output_ref`
        /// for a convenient way to construct testing output refs.
        fn with_utxo(
            mut self,
            output_ref: OutputRef,
            payload: Coin,
            owner: H256
        ) -> Self {
            let output = Output {
                payload: payload,
                owner: owner
            };
            self.utxos.push((output_ref, output));
            self
        }

        /// Add a preheader to the storage.
        ///
        /// In normal execution `open_block` stores a header in storage
        /// before any extrinsics are applied. This function allows setting up
        /// a test case with a stored pre-header.
        ///
        /// Rather than passing in a header, we pass in parts of it. This ensures
        /// that a realistic pre-header (without extrinsics root or state root)
        /// is stored.
        ///
        /// Although a partial digest would be part of the pre-header, we have no
        /// use case for setting one, so it is also omitted here.
        fn with_pre_header(mut self, parent_hash: H256, number: u32) -> Self {
            let h = Header {
                parent_hash,
                number,
                state_root: H256::zero(),
                extrinsics_root: H256::zero(),
                digest: Default::default(),
            };

            self.pre_header = Some(h);
            self
        }

        /// Add a noted extrinsic to the state.
        ///
        /// In normal block authoring, extrinsics are noted in state as they are
        /// applied so that an extrinsics root can be calculated at the end of the
        /// block. This function allows setting up a test case with some extrinsics
        /// already noted.
        ///
        /// The extrinsic is already encoded so that it doesn't have to be a proper
        /// extrinsic, but can just be some example bytes.
        fn with_noted_extrinsic(mut self, ext: Vec<u8>) -> Self {
            self.noted_extrinsics.push(ext);
            self
        }

        /// Build the test externalities with all the utxos already stored
        fn build(self) -> TestExternalities {
            let mut ext = TestExternalities::default();

            // Write all the utxos
            for (output_ref, output) in self.utxos {
                ext.insert(output_ref.encode(), output.encode());
            }

            // Write a pre-header. If none was supplied, create and use a default one.
            let pre_header = self.pre_header.unwrap_or(Header {
                parent_hash: Default::default(),
                number: 0,
                state_root: H256::zero(),
                extrinsics_root: H256::zero(),
                digest: Default::default(),
            });
            ext.insert(HEADER_KEY.to_vec(), pre_header.encode());

            // Write a block height.
            ext.insert(HEIGHT_KEY.to_vec(), pre_header.number.encode());

            // Write the noted extrinsics
            ext.insert(EXTRINSIC_KEY.to_vec(), self.noted_extrinsics.encode());

            ext
        }
    }

    #[test]
    fn validate_no_inputs_fails() {
        let tx = TestTransactionBuilder::default().build();
        let result = Executive::validate_griffin_transaction(&tx);

        assert_eq!(result, Err(UtxoError::NoInputs));
    }

    #[test]
    fn validate_with_input_works() {
        let output_ref = mock_output_ref(0, 0);
        let owner = mock_owner(0);

        ExternalityBuilder::default()
            .with_utxo(output_ref.clone(), 1, owner)
            .build()
            .execute_with(|| {
                let input = Input {
                    output_ref,
                };

                let tx = TestTransactionBuilder::default()
                    .with_input(input)
                    .build();

                let vt = Executive::validate_griffin_transaction(&tx).unwrap();

                let expected_result = ValidTransactionBuilder::default().into();

                assert_eq!(vt, expected_result);
            });
    }


    #[test]
    fn validate_with_input_and_output_works() {
        let output_ref = mock_output_ref(0, 0);
        let owner = mock_owner(0);

        ExternalityBuilder::default()
            .with_utxo(output_ref.clone(), 1, owner)
            .build()
            .execute_with(|| {
                let input = Input {
                    output_ref,
                };
                let output = Output {
                    payload: 1,
                    owner: owner,
                };
                let tx = TestTransactionBuilder::default()
                    .with_input(input)
                    .with_output(output)
                    .build();

                // This is a real transaction, so we need to calculate a real OutputRef
                let tx_hash = BlakeTwo256::hash_of(&tx.encode());
                let output_ref = OutputRef { tx_hash, index: 0 };

                let vt = Executive::validate_griffin_transaction(&tx).unwrap();

                let expected_result = ValidTransactionBuilder::default()
                    .and_provides(output_ref)
                    .into();

                assert_eq!(vt, expected_result);
             });
    }

    #[test]
    fn validate_with_missing_input_works() {
        ExternalityBuilder::default().build().execute_with(|| {
            let output_ref = mock_output_ref(0, 0);
            let input = Input {
                output_ref: output_ref.clone(),
            };

            let tx = TestTransactionBuilder::default()
                .with_input(input)
                .build();

            let vt = Executive::validate_griffin_transaction(&tx).unwrap();

            let expected_result = ValidTransactionBuilder::default()
                .and_requires(output_ref)
                .into();

            assert_eq!(vt, expected_result);
        });
    }

    #[test]
    fn validate_with_duplicate_input_fails() {
        let output_ref = mock_output_ref(0, 0);
        let owner = mock_owner(0);

        ExternalityBuilder::default()
            .with_utxo(output_ref.clone(), 1, owner)
            .build()
            .execute_with(|| {
                let input = Input {
                    output_ref,
                };

                let tx = TestTransactionBuilder::default()
                    .with_input(input.clone())
                    .with_input(input)
                    .build();

                let result = Executive::validate_griffin_transaction(&tx);

                assert_eq!(result, Err(UtxoError::DuplicateInput));
            });
    }

    #[test]
    fn apply_no_inputs_fails() {
        ExternalityBuilder::default().build().execute_with(|| {
            let tx = TestTransactionBuilder::default().build();
            let result = Executive::apply_griffin_transaction(tx);

            assert_eq!(result, Err(UtxoError::NoInputs));
        });
    }

    #[test]
    fn apply_with_missing_input_fails() {
        ExternalityBuilder::default().build().execute_with(|| {
            let output_ref = mock_output_ref(0, 0);
            let input = Input {
                output_ref: output_ref.clone(),
            };

            let tx = TestTransactionBuilder::default()
                .with_input(input)
                .build();

            let vt = Executive::apply_griffin_transaction(tx);

            assert_eq!(vt, Err(UtxoError::MissingInput));
        });
    }

    #[test]
    fn update_storage_consumes_input() {
        let output_ref = mock_output_ref(0, 0);
        let owner = mock_owner(0);

        ExternalityBuilder::default()
            .with_utxo(output_ref.clone(), 1, owner)
            .build()
            .execute_with(|| {
                let input = Input {
                    output_ref: output_ref.clone(),
                };

                let tx = TestTransactionBuilder::default()
                    .with_input(input)
                    .build();

                // Commit the tx to storage
                Executive::update_storage(tx);

                // Check whether the Input is still in storage
                assert!(!sp_io::storage::exists(&output_ref.encode()));
            });
    }

    #[test]
    fn update_storage_adds_output() {
        ExternalityBuilder::default().build().execute_with(|| {
            let output = Output {
                payload: 1,
                owner: mock_owner(0),
            };

            let tx = TestTransactionBuilder::default()
                .with_output(output.clone())
                .build();

            let tx_hash = BlakeTwo256::hash_of(&tx.encode());
            let output_ref = OutputRef { tx_hash, index: 0 };

            // Commit the tx to storage
            Executive::update_storage(tx);

            // Check whether the Output has been written to storage and the proper value is stored
            let stored_bytes = sp_io::storage::get(&output_ref.encode()).unwrap();
            let stored_value = Output::decode(&mut &stored_bytes[..]).unwrap();
            assert_eq!(stored_value, output);
        });
    }

    #[test]
    fn open_block_works() {
        let header = Header {
            parent_hash: H256::repeat_byte(5),
            number: 5,
            state_root: H256::repeat_byte(6),
            extrinsics_root: H256::repeat_byte(7),
            digest: Default::default(),
        };

        ExternalityBuilder::default().build().execute_with(|| {
            // Call open block which just writes the header to storage
            Executive::open_block(&header);

            // Fetch the header back out of storage
            let retrieved_header = sp_io::storage::get(HEADER_KEY)
                .and_then(|d| Header::decode(&mut &*d).ok())
                .expect("Open block should have written a header to storage");

            // Make sure the header that came out is the same one that went in.
            assert_eq!(retrieved_header, header);
        });
    }

    #[test]
    fn apply_valid_extrinsic_work() {
        let output_ref = mock_output_ref(0, 0);
        let owner = mock_owner(0);

        ExternalityBuilder::default()
            .with_utxo(output_ref.clone(), 1, owner)
            .build()
            .execute_with(|| {
                let input = Input {
                    output_ref,
                };
                
                let tx = TestTransactionBuilder::default()
                    .with_input(input)
                    .build();

                let apply_result = Executive::apply_extrinsic(tx.clone());

                // Make sure the returned result is Ok
                assert_eq!(apply_result, Ok(Ok(())));

                // Make sure the transaction is noted in storage
                let noted_extrinsics = sp_io::storage::get(EXTRINSIC_KEY)
                    .and_then(|d| <Vec<Vec<u8>>>::decode(&mut &*d).ok())
                    .unwrap_or_default();

                assert_eq!(noted_extrinsics, vec![tx.encode()]);
            });
    }

    #[test]
    fn close_block_works() {
        let parent_hash = H256::repeat_byte(5);
        let block_number = 6;
        let extrinsic = vec![1, 2, 3];
        ExternalityBuilder::default()
            .with_pre_header(parent_hash, block_number)
            .with_noted_extrinsic(extrinsic.clone())
            .build()
            .execute_with(|| {
                let returned_header = Executive::close_block();

                // Make sure the header is as we expected
                let raw_state_root = &sp_io::storage::root(StateVersion::V1)[..];
                let state_root = H256::decode(&mut &raw_state_root[..]).unwrap();
                let expected_header = Header {
                    parent_hash,
                    number: block_number,
                    state_root,
                    extrinsics_root: BlakeTwo256::ordered_trie_root(
                        vec![extrinsic],
                        StateVersion::V0,
                    ),
                    digest: Default::default(),
                };

                assert_eq!(returned_header, expected_header);

                // Make sure the transient storage has been removed
                assert!(!sp_io::storage::exists(HEADER_KEY));
                assert!(!sp_io::storage::exists(EXTRINSIC_KEY));
            });
    }

    #[test]
    fn execute_empty_block_works() {
        ExternalityBuilder::default().build().execute_with(|| {
            let b = Block {
                header: Header {
                    parent_hash: H256::zero(),
                    number: 6,
                    state_root: array_bytes::hex_n_into_unchecked(
                        "cc2d78f5977b6e9e16f4417f60cbd7edaad0c39a6a7cd21281e847da7dd210b9",
                    ),
                    extrinsics_root: array_bytes::hex_n_into_unchecked(
                        "03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314",
                    ),
                    digest: Default::default(),
                },
                extrinsics: Vec::new(),
            };

            Executive::execute_block(b);
        });
    }

    #[test]
    fn execute_block_with_transaction_works() {
        let output_ref = mock_output_ref(0, 0);
        let owner = mock_owner(0);

        ExternalityBuilder::default()
            .with_utxo(output_ref.clone(), 1, owner)
            .build()
            .execute_with(|| {
                let input = Input {
                    output_ref,
                };

                let b = Block {
                    header: Header {
                        parent_hash: H256::zero(),
                        number: 6,
                        state_root: array_bytes::hex_n_into_unchecked(
                            "cc2d78f5977b6e9e16f4417f60cbd7edaad0c39a6a7cd21281e847da7dd210b9",
                        ),
                        extrinsics_root: array_bytes::hex_n_into_unchecked(
                            "aaf645b6a9d8daa189db456a7bfc42a955e95dd5ddcb4d2549d96b532ec50328",
                        ),
                        digest: Default::default(),
                    },
                    extrinsics: vec![TestTransactionBuilder::default().with_input(input).build()],
                };

                Executive::execute_block(b);
            });
    }

    #[test]
    #[should_panic(expected = "state root mismatch")]
    fn execute_block_state_root_mismatch() {
        ExternalityBuilder::default().build().execute_with(|| {
            let b = Block {
                header: Header {
                    parent_hash: H256::zero(),
                    number: 6,
                    state_root: H256::zero(),
                    extrinsics_root: array_bytes::hex_n_into_unchecked(
                        "03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314",
                    ),
                    digest: Default::default(),
                },
                extrinsics: Vec::new(),
            };

            Executive::execute_block(b);
        });
    }

    #[test]
    #[should_panic(expected = "extrinsics root mismatch")]
    fn execute_block_extrinsics_root_mismatch() {
        ExternalityBuilder::default().build().execute_with(|| {
            let b = Block {
                header: Header {
                    parent_hash: H256::zero(),
                    number: 6,
                    state_root: array_bytes::hex_n_into_unchecked(
                        "cc2d78f5977b6e9e16f4417f60cbd7edaad0c39a6a7cd21281e847da7dd210b9",
                    ),
                    extrinsics_root: H256::zero(),
                    digest: Default::default(),
                },
                extrinsics: Vec::new(),
            };

            Executive::execute_block(b);
        });
    }
}
