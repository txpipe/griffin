//! Wallet features related to paying to a script address, spending a script input and minting an asset.

use crate::{
    cli::{MintAssetArgs, PayToScriptArgs, SpendScriptArgs},
    sync,
};
use anyhow::anyhow;
use griffin_core::{
    checks_interface::{babbage_minted_tx_from_cbor, babbage_tx_to_cbor, MIN_COIN_PER_OUTPUT},
    genesis::SHAWN_ADDRESS,
    pallas_primitives::babbage::{
        MintedTx, PlutusData as PallasPlutusData, Tx as PallasTransaction,
    },
    pallas_primitives::Fragment,
    pallas_traverse::OriginalHash,
    types::{
        address_from_hex, compute_plutus_v2_script_hash, value_leq, Address, AssetName, Datum,
        ExUnits, Input, Multiasset, Output, PlutusData, PlutusScript, PolicyId, Redeemer,
        RedeemerTag, Transaction, VKeyWitness, Value,
    },
    uplc::tx::apply_params_to_script,
};
use jsonrpsee::{core::client::ClientT, http_client::HttpClient, rpc_params};
use parity_scale_codec::Encode;
use sc_keystore::LocalKeystore;
use sled::Db;
use sp_core::ed25519::Public;
use sp_runtime::traits::{BlakeTwo256, Hash};
use std::vec;

pub async fn pay_to_script(
    db: &Db,
    client: &HttpClient,
    keystore: &LocalKeystore,
    args: PayToScriptArgs,
) -> anyhow::Result<()> {
    log::debug!("The args are:: {:?}", args);

    let num_pol = args.policy.len();
    let num_nam = args.name.len();
    let num_tok = args.token_amount.len();
    if num_pol > num_nam {
        Err(anyhow!(
            "Policy ID {} does not correspond to any asset name.",
            args.policy[num_pol - 1],
        ))?;
    }
    if num_nam > num_tok {
        Err(anyhow!(
            "Missing token amount for asset {:?}.",
            args.name[num_nam - 1],
        ))?;
    }
    if (num_tok != 0) & ((num_nam == 0) | (num_pol == 0)) {
        Err(anyhow!("Missing policy ID(s) and/or asset name."))?;
    }

    // Construct a template Transaction to push coins into later
    let mut transaction = Transaction::from((Vec::new(), Vec::new()));

    // Total amount in inputs
    let mut input_value: Value = Value::Coin(0);
    for input in &args.input {
        if let Some((_owner_pubkey, amount, _)) = sync::get_unspent(db, input)? {
            input_value += amount;
        } else {
            log::info!(
                "Warning: User-specified utxo {:x?} not found in wallet database",
                input
            );
        }
    }

    let coin_amount = args.amount.unwrap_or(0);
    // Total amount in outputs
    let mut output_value: Value = Value::Coin(coin_amount);

    let last_policy: Option<&PolicyId> = args.policy.last().clone();
    for count in 0..num_pol {
        output_value += <_>::from((
            args.policy[count],
            <_>::from(args.name[count].clone()),
            args.token_amount[count],
        ));
    }
    let last_name: Option<&String> = args.name.last().clone();
    for count in num_pol..num_nam {
        output_value += <_>::from((
            last_policy.unwrap().clone(),
            <_>::from(args.name[count].clone()),
            args.token_amount[count],
        ));
    }
    for count in num_nam..num_tok {
        output_value += <_>::from((
            last_policy.unwrap().clone(),
            <AssetName>::from(last_name.unwrap().clone()),
            args.token_amount[count],
        ));
    }

    let script_hex: String = std::fs::read_to_string(args.script_hex_file)?;
    let script = if args.script_params_cbor_file != "" {
        let script_params_cbor: String = std::fs::read_to_string(args.script_params_cbor_file)?;
        let script_params_data =
            PallasPlutusData::from(PlutusData(hex::decode(script_params_cbor).unwrap()));
        PlutusScript(
            apply_params_to_script(
                script_params_data.encode_fragment().unwrap().as_slice(),
                hex::decode(script_hex).unwrap().as_slice(),
            )
            .unwrap(),
        )
    } else {
        PlutusScript(hex::decode(script_hex).unwrap())
    };
    let script_hash = compute_plutus_v2_script_hash(script.clone());
    let script_address = Address(hex::decode("70".to_owned() + &hex::encode(script_hash)).unwrap());

    // Construct the output and then push to the transaction
    let output = if args.datum_cbor_file != "" {
        let datum_hex: String = std::fs::read_to_string(args.datum_cbor_file)?;
        let datum: Datum = Datum(hex::decode(datum_hex).unwrap());
        Output::from((script_address, output_value.clone(), datum))
    } else {
        Output::from((script_address, output_value.clone()))
    };
    transaction.transaction_body.outputs.push(output);

    // If the supplied inputs surpass output amount, we redirect the rest to Shawn
    if value_leq(&output_value, &input_value) {
        let remainder: Value = input_value - output_value;
        if !remainder.is_null() {
            println!("Note: Excess input amount goes to Shawn.");
            let output = Output::from((address_from_hex(SHAWN_ADDRESS), remainder));
            transaction.transaction_body.outputs.push(output);
        }
    }

    // Push each input to the transaction.
    for input in &args.input {
        transaction.transaction_body.inputs.push(input.clone());
    }

    // FIXME: Duplicate code
    let pallas_tx: PallasTransaction = <_>::from(transaction.clone());
    let cbor_bytes: Vec<u8> = babbage_tx_to_cbor(&pallas_tx);
    let mtx: MintedTx = babbage_minted_tx_from_cbor(&cbor_bytes);
    let tx_hash: &Vec<u8> = &Vec::from(mtx.transaction_body.original_hash().as_ref());
    log::debug!("Original tx_body hash is: {:#x?}", tx_hash);

    let mut witnesses: Vec<VKeyWitness> = Vec::new();
    for witness in &args.witness {
        let vkey: Vec<u8> = Vec::from(witness.0);
        let public = Public::from_h256(*witness);
        let signature: Vec<u8> =
            Vec::from(crate::keystore::sign_with(keystore, &public, tx_hash)?.0);
        witnesses.push(VKeyWitness::from((vkey, signature)));
    }
    transaction.transaction_witness_set = <_>::from(witnesses);

    log::debug!("Griffin transaction is: {:#x?}", transaction);
    let pallas_tx: PallasTransaction = <_>::from(transaction.clone());
    log::debug!("Babbage transaction is: {:#x?}", pallas_tx);

    // Send the transaction
    let genesis_spend_hex = hex::encode(Encode::encode(&transaction));
    let params = rpc_params![genesis_spend_hex];
    let genesis_spend_response: Result<String, _> =
        client.request("author_submitExtrinsic", params).await;
    log::info!(
        "Node's response to spend transaction: {:?}",
        genesis_spend_response
    );
    if let Err(_) = genesis_spend_response {
        Err(anyhow!("Node did not accept the transaction"))?;
    } else {
        println!("Transaction queued. When accepted, the following UTxOs will become available:");
        // Print new output refs for user to check later
        let tx_hash = <BlakeTwo256 as Hash>::hash_of(&Encode::encode(&transaction));
        for (i, output) in transaction.transaction_body.outputs.iter().enumerate() {
            let new_value_ref = Input {
                tx_hash,
                index: i as u32,
            };
            let amount = &output.value;

            println!(
                "{:?} worth {amount:?}.",
                hex::encode(Encode::encode(&new_value_ref))
            );
        }
    }

    Ok(())
}

pub async fn spend_script(
    db: &Db,
    client: &HttpClient,
    keystore: &LocalKeystore,
    args: SpendScriptArgs,
) -> anyhow::Result<()> {
    log::debug!("The args are:: {:?}", args);

    // Construct a template Transaction to push coins into later
    let mut transaction = Transaction::from((Vec::new(), Vec::new()));

    if let Some((_, input_value, _)) = sync::get_unspent(db, &args.input)? {
        let script_hex: String = std::fs::read_to_string(args.script_hex_file)?;
        let script = if args.script_params_cbor_file != "" {
            let script_params_cbor: String = std::fs::read_to_string(args.script_params_cbor_file)?;
            let script_params_data =
                PallasPlutusData::from(PlutusData(hex::decode(script_params_cbor).unwrap()));
            PlutusScript(
                apply_params_to_script(
                    script_params_data.encode_fragment().unwrap().as_slice(),
                    hex::decode(script_hex).unwrap().as_slice(),
                )
                .unwrap(),
            )
        } else {
            PlutusScript(hex::decode(script_hex).unwrap())
        };

        let redeemer_hex: String = std::fs::read_to_string(args.redeemer_cbor_file)?;
        let redeemer = Redeemer {
            tag: RedeemerTag::Spend,
            index: 0,
            data: PlutusData(hex::decode(redeemer_hex).unwrap()),
            ex_units: ExUnits {
                mem: 661056,
                steps: 159759842,
            },
        };

        println!("Note: Excess input amount goes to Shawn.");
        let output = Output::from((address_from_hex(SHAWN_ADDRESS), input_value));

        transaction.transaction_body.outputs.push(output);
        transaction.transaction_body.inputs.push(args.input.clone());
        transaction.transaction_body.required_signers = Some(args.required_signers);

        // FIXME: Duplicate code
        let pallas_tx: PallasTransaction = <_>::from(transaction.clone());
        let cbor_bytes: Vec<u8> = babbage_tx_to_cbor(&pallas_tx);
        let mtx: MintedTx = babbage_minted_tx_from_cbor(&cbor_bytes);
        let tx_hash: &Vec<u8> = &Vec::from(mtx.transaction_body.original_hash().as_ref());
        log::debug!("Original tx_body hash is: {:#x?}", tx_hash);

        let mut witnesses: Vec<VKeyWitness> = Vec::new();
        for witness in &args.witness {
            let vkey: Vec<u8> = Vec::from(witness.0);
            let public = Public::from_h256(*witness);
            let signature: Vec<u8> =
                Vec::from(crate::keystore::sign_with(keystore, &public, tx_hash)?.0);
            witnesses.push(VKeyWitness::from((vkey, signature)));
        }
        transaction.transaction_witness_set = <_>::from(witnesses);
        transaction.transaction_witness_set.plutus_script = Some(vec![script]);
        transaction.transaction_witness_set.redeemer = Some(vec![redeemer]);

        log::debug!("Griffin transaction is: {:#x?}", transaction);
        let pallas_tx: PallasTransaction = <_>::from(transaction.clone());
        log::debug!("Babbage transaction is: {:#x?}", pallas_tx);

        // Send the transaction
        let genesis_spend_hex = hex::encode(Encode::encode(&transaction));
        let params = rpc_params![genesis_spend_hex];
        let genesis_spend_response: Result<String, _> =
            client.request("author_submitExtrinsic", params).await;
        log::info!(
            "Node's response to spend transaction: {:?}",
            genesis_spend_response
        );
        if let Err(_) = genesis_spend_response {
            Err(anyhow!("Node did not accept the transaction"))?;
        } else {
            println!(
                "Transaction queued. When accepted, the following UTxOs will become available:"
            );
            // Print new output refs for user to check later
            let tx_hash = <BlakeTwo256 as Hash>::hash_of(&Encode::encode(&transaction));
            for (i, output) in transaction.transaction_body.outputs.iter().enumerate() {
                let new_value_ref = Input {
                    tx_hash,
                    index: i as u32,
                };
                let amount = &output.value;

                println!(
                    "{:?} worth {amount:?}.",
                    hex::encode(Encode::encode(&new_value_ref))
                );
            }
        }

        Ok(())
    } else {
        Err(anyhow!(
            "User-specified utxo {:x?} not found in wallet database",
            &args.input,
        ))?
    }
}

pub async fn mint_asset(
    db: &Db,
    client: &HttpClient,
    keystore: &LocalKeystore,
    args: MintAssetArgs,
) -> anyhow::Result<()> {
    log::debug!("The args are:: {:?}", args);

    if let Some((_, input_value, _)) = sync::get_unspent(db, &args.input)? {
        let script_hex: String = std::fs::read_to_string(args.script_hex_file)?;

        let script = if args.script_params_cbor_file != "" {
            let script_params_cbor: String = std::fs::read_to_string(args.script_params_cbor_file)?;
            let script_params_data =
                PallasPlutusData::from(PlutusData(hex::decode(script_params_cbor).unwrap()));
            PlutusScript(
                apply_params_to_script(
                    script_params_data.encode_fragment().unwrap().as_slice(),
                    hex::decode(script_hex).unwrap().as_slice(),
                )
                .unwrap(),
            )
        } else {
            PlutusScript(hex::decode(script_hex).unwrap())
        };
        let policy = compute_plutus_v2_script_hash(script.clone());

        let minted_value = Value::from((
            policy,
            AssetName::from(args.name.clone()),
            args.token_amount,
        ));
        let mint_output = Output::from((
            args.recipient,
            minted_value + Value::Coin(MIN_COIN_PER_OUTPUT),
        ));

        println!("Note: Excess input amount goes to Shawn.");
        let return_output = Output::from((
            address_from_hex(SHAWN_ADDRESS),
            input_value - Value::Coin(MIN_COIN_PER_OUTPUT),
        ));

        let redeemer_hex: String = std::fs::read_to_string(args.redeemer_cbor_file)?;
        let redeemer = Redeemer {
            tag: RedeemerTag::Mint,
            index: 0,
            data: PlutusData(hex::decode(redeemer_hex).unwrap()),
            ex_units: ExUnits {
                mem: 661056,
                steps: 159759842,
            },
        };

        let mut transaction = Transaction::from((Vec::new(), Vec::new()));
        transaction.transaction_body.outputs.push(mint_output);
        transaction.transaction_body.outputs.push(return_output);
        transaction.transaction_body.inputs.push(args.input.clone());

        let mint = Some(Multiasset::from((
            policy,
            AssetName::from(args.name),
            args.token_amount as i64,
        )));
        transaction.transaction_body.mint = mint;

        // FIXME: Duplicate code
        let pallas_tx: PallasTransaction = <_>::from(transaction.clone());
        let cbor_bytes: Vec<u8> = babbage_tx_to_cbor(&pallas_tx);
        let mtx: MintedTx = babbage_minted_tx_from_cbor(&cbor_bytes);
        let tx_hash: &Vec<u8> = &Vec::from(mtx.transaction_body.original_hash().as_ref());
        log::debug!("Original tx_body hash is: {:#x?}", tx_hash);

        let mut witnesses: Vec<VKeyWitness> = Vec::new();
        for witness in &args.witness {
            let vkey: Vec<u8> = Vec::from(witness.0);
            let public = Public::from_h256(*witness);
            let signature: Vec<u8> =
                Vec::from(crate::keystore::sign_with(keystore, &public, tx_hash)?.0);
            witnesses.push(VKeyWitness::from((vkey, signature)));
        }
        transaction.transaction_witness_set = <_>::from(witnesses);
        transaction.transaction_witness_set.plutus_script = Some(vec![script]);
        transaction.transaction_witness_set.redeemer = Some(vec![redeemer]);

        log::debug!("Griffin transaction is: {:#x?}", transaction);
        let pallas_tx: PallasTransaction = <_>::from(transaction.clone());
        log::debug!("Babbage transaction is: {:#x?}", pallas_tx);

        // Send the transaction
        let genesis_spend_hex = hex::encode(Encode::encode(&transaction));
        let params = rpc_params![genesis_spend_hex];
        let genesis_spend_response: Result<String, _> =
            client.request("author_submitExtrinsic", params).await;
        log::info!(
            "Node's response to spend transaction: {:?}",
            genesis_spend_response
        );
        if let Err(_) = genesis_spend_response {
            Err(anyhow!("Node did not accept the transaction"))?;
        } else {
            println!(
                "Transaction queued. When accepted, the following UTxOs will become available:"
            );
            // Print new output refs for user to check later
            let tx_hash = <BlakeTwo256 as Hash>::hash_of(&Encode::encode(&transaction));
            for (i, output) in transaction.transaction_body.outputs.iter().enumerate() {
                let new_value_ref = Input {
                    tx_hash,
                    index: i as u32,
                };
                let amount = &output.value;

                println!(
                    "{:?} worth {amount:?}.",
                    hex::encode(Encode::encode(&new_value_ref))
                );
            }
        }

        Ok(())
    } else {
        Err(anyhow!(
            "User-specified utxo {:x?} not found in wallet database",
            &args.input,
        ))?
    }
}

#[test]
fn test_phase2_one_shot_mp() {
    use core::str::FromStr;
    use griffin_core::checks_interface::conway_minted_tx_from_cbor;
    use griffin_core::h224::H224;
    use griffin_core::pallas_codec::minicbor;
    use griffin_core::pallas_codec::utils::{
        Int,
        MaybeIndefArray::{Def, Indef},
    };
    use griffin_core::pallas_crypto::hash::Hash;
    use griffin_core::pallas_primitives::conway::{
        BigInt, BoundedBytes, Constr, MintedTx as ConwayMintedTx, PlutusData as PallasPlutusData,
        TransactionInput, TransactionOutput,
    };
    use griffin_core::pallas_primitives::Fragment;
    use griffin_core::types::{
        compute_plutus_v2_script_hash, Address, AssetName, ExUnits, Input, Multiasset, Output,
        PlutusData, PlutusScript, Redeemer, RedeemerTag, Value,
    };
    use griffin_core::uplc::tx::{
        apply_params_to_script, eval_phase_two, ResolvedInput, SlotConfig,
    };
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
fn test_phase2_aiken_hello_world() {
    use core::str::FromStr;
    use griffin_core::checks_interface::conway_minted_tx_from_cbor;
    use griffin_core::h224::H224;
    use griffin_core::pallas_codec::utils::MaybeIndefArray::Indef;
    use griffin_core::pallas_crypto::hash::Hash;
    use griffin_core::pallas_primitives::conway::{
        BoundedBytes, Constr, MintedTx as ConwayMintedTx, PlutusData as PallasPlutusData,
        TransactionInput, TransactionOutput,
    };
    use griffin_core::types::{
        compute_plutus_v2_script_hash, Address, Datum, ExUnits, Input, Output, PlutusData,
        PlutusScript, Redeemer, RedeemerTag, VKeyWitness, Value,
    };
    use griffin_core::uplc::tx::{eval_phase_two, ResolvedInput, SlotConfig};
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
fn test_phase2_ppp_vesting() {
    /* TESTED CONTRACT (extracted from Plutus Pioneer Program):

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
    use core::str::FromStr;
    use griffin_core::checks_interface::conway_minted_tx_from_cbor;
    use griffin_core::h224::H224;
    use griffin_core::pallas_codec::minicbor;
    use griffin_core::pallas_codec::utils::{
        Int,
        MaybeIndefArray::{Def, Indef},
    };
    use griffin_core::pallas_crypto::hash::Hash;
    use griffin_core::pallas_primitives::conway::{
        BigInt, BoundedBytes, Constr, MintedTx as ConwayMintedTx, PlutusData as PallasPlutusData,
        TransactionInput, TransactionOutput,
    };
    use griffin_core::types::{
        Address, Datum, ExUnits, Input, Output, PlutusData, PlutusScript, Redeemer, RedeemerTag,
        Value,
    };
    use griffin_core::uplc::tx::{eval_phase_two, ResolvedInput, SlotConfig};
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
