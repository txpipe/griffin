//! Wallet features related to spending money and checking balances.

use crate::{
    cli::{MintAssetArgs, MintCoinArgs, PayToScriptArgs, SpendScriptArgs, SpendValueArgs},
    rpc::fetch_storage,
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

#[allow(dead_code)]
#[doc(hidden)]
/// Create and send a transaction that mints the coins on the network
pub async fn mint_coins(client: &HttpClient, args: MintCoinArgs) -> anyhow::Result<()> {
    log::debug!("The args are:: {:?}", args);

    let mut transaction = Transaction::from((
        Vec::new(),
        vec![Output::from((args.recipient, args.amount))],
    ));

    // The input appears as a new output.
    let utxo = fetch_storage(&args.input, client).await?;
    transaction.transaction_body.inputs.push(args.input.clone());
    transaction.transaction_body.outputs.push(utxo);

    let encoded_tx = hex::encode(Encode::encode(&transaction));
    let params = rpc_params![encoded_tx];
    let spawn_response: Result<String, _> = client.request("author_submitExtrinsic", params).await;

    log::info!(
        "Node's response to mint-coin transaction: {:?}",
        spawn_response
    );

    let minted_coin_ref = Input {
        tx_hash: <BlakeTwo256 as Hash>::hash_of(&Encode::encode(&transaction)),
        index: 0,
    };
    let output = &transaction.transaction_body.outputs[0];
    let amount = &output.value;
    println!(
        "Minted {:?} worth {amount:?}. ",
        hex::encode(Encode::encode(&minted_coin_ref))
    );

    Ok(())
}

/// Create and submit a transaction that spends `Value`. Any surplus from inputs
/// is sent to Shawn's address.
///
/// Local checks of balance are omitted.
pub async fn spend_value(
    db: &Db,
    client: &HttpClient,
    keystore: &LocalKeystore,
    args: SpendValueArgs,
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

    // Construct the output and then push to the transaction
    let output = Output::from((args.recipient.clone(), output_value.clone()));
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
    let script = PlutusScript(hex::decode(script_hex).unwrap());
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
        let script = PlutusScript(hex::decode(script_hex).unwrap());

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

/// Given an output ref, fetch the details about its value from the node's
/// storage.
pub async fn get_coin_from_storage(input: &Input, client: &HttpClient) -> anyhow::Result<Value> {
    let utxo = fetch_storage(input, client).await?;
    let coin_in_storage: Value = utxo.value;

    Ok(coin_in_storage)
}

/// Apply a transaction to the local database, storing the value.
pub(crate) fn apply_transaction(
    db: &Db,
    tx_hash: <BlakeTwo256 as Hash>::Output,
    index: u32,
    output: &Output,
) -> anyhow::Result<()> {
    let input = Input { tx_hash, index };

    crate::sync::add_unspent_output(
        db,
        &input,
        &output.address,
        &output.value,
        &output.datum_option,
    )
}
