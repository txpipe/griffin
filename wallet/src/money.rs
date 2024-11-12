//! Wallet features related to spending money and checking balances.

use crate::{
    cli::{
        MintCoinArgs, SpendArgs, SpendValueArgs,
    },
    rpc::fetch_storage,
    sync,
};
use anyhow::anyhow;
use jsonrpsee::{core::client::ClientT, http_client::HttpClient, rpc_params};
use parity_scale_codec::Encode;
use sc_keystore::LocalKeystore;
use sled::Db;
use sp_runtime::traits::{BlakeTwo256, Hash};
use griffin_core::{
    types::{
        Value, Input, Output, Transaction, VKeyWitness, address_from_hex,
        PolicyId, AssetName, value_leq,
    },
    checks_interface::{
        babbage_tx_to_cbor,
        babbage_minted_tx_from_cbor,
    },
    pallas_traverse::OriginalHash,
    pallas_primitives::babbage::{
    Tx as PallasTransaction, MintedTx,
    },
    genesis::SHAWN_ADDRESS,
};
use sp_core::ed25519::Public;
use std::vec;

#[allow(dead_code)]
/// Create and send a transaction that mints the coins on the network
pub async fn mint_coins(
    client: &HttpClient,
    args: MintCoinArgs,
) -> anyhow::Result<()> {
    log::debug!("The args are:: {:?}", args);

    let mut transaction = Transaction::from((
            Vec::new(),
            vec![Output::from((args.recipient, args.amount))]
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

/// Create and send a transaction that spends coins on the network
pub async fn spend_coins(
    db: &Db,
    client: &HttpClient,
    keystore: &LocalKeystore,
    args: SpendArgs,
) -> anyhow::Result<()> {
    log::debug!("The args are:: {:?}", args);

    // Construct a template Transaction to push coins into later
    let mut transaction = Transaction::from((Vec::new(), Vec::new()));

    // Construct each output and then push to the transaction
    let mut total_amount: u64 = 0;
    for amount in &args.amount {
        let output = Output::from((args.recipient.clone(), *amount));
        total_amount += *amount;
        transaction.transaction_body.outputs.push(output);
    }

    // The total input set will consist of any manually chosen inputs
    let mut total_input_amount: u64 = 0;
    for input in &args.input {
        if let Some((_owner_pubkey, amount, _)) = sync::get_unspent(db, input)? {
            total_input_amount += match amount {
                Value::Coin(c) => c,
                _ => 0
            };
        } else {
            log::info!(
                "Warning: User-specified utxo {:x?} not found in wallet database",
                input
            );
        }
    }

    // If the supplied inputs are not valuable enough to cover the output amount
    // we abort in error.
    if total_input_amount < total_amount {
        println!(
            "Warning: Total input amount (in wallet database) insufficient to pay for outputs."
        );
    }

    // If the supplied inputs surpass output amount, we redirect the rest to Shawn
    if total_input_amount > total_amount {
        println!(
            "Note: Excess input amount goes to Shawn."
        );
        let output = Output::from((address_from_hex(SHAWN_ADDRESS), total_input_amount - total_amount));
        transaction.transaction_body.outputs.push(output);
    }

    // Make sure each input decodes and is still present in the node's storage,
    // and then push to transaction.
    for input in &args.input {
        //  get_coin_from_storage(input, client).await?;
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
        let signature: Vec<u8> = Vec::from(crate::keystore::sign_with(
            keystore, &public, tx_hash
        )?.0);
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
            let new_coin_ref = Input {
                tx_hash,
                index: i as u32,
            };
            let amount = &output.value;

            println!(
                "{:?} worth {amount:?}.",
                hex::encode(Encode::encode(&new_coin_ref))
            );
        }
    }
    
    Ok(())
}

/// Create and submit a transaction that spends `Value`.
/// We omit the local checks of balance.
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
            args.policy[num_pol-1],
        ))?;
    }
    if num_nam > num_tok {
        Err(anyhow!(
            "Missing amount for asset {:?}.",
            args.name[num_nam-1],
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
            println!(
                "Note: Excess input amount goes to Shawn."
            );
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
        let signature: Vec<u8> = Vec::from(crate::keystore::sign_with(
            keystore, &public, tx_hash
        )?.0);
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

/// Given an output ref, fetch the details about its value from the node's
/// storage.
pub async fn get_coin_from_storage(
    input: &Input,
    client: &HttpClient,
) -> anyhow::Result<Value> {
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

    crate::sync::add_unspent_output(db,
                                    &input,
                                    &output.address,
                                    &output.value,
                                    &output.datum_option
    )
}
