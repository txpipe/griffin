//! Wallet features related to spending money and checking balances.

use crate::{cli::MintCoinArgs, cli::SpendArgs, rpc::fetch_storage, sync};

use anyhow::anyhow;
use jsonrpsee::{core::client::ClientT, http_client::HttpClient, rpc_params};
use parity_scale_codec::Encode;
use sc_keystore::LocalKeystore;
use sled::Db;
use sp_runtime::traits::{BlakeTwo256, Hash};
use griffin_core::{
    types::{Coin, Input, Output, OutputRef, Transaction},
};

/// Create and send a transaction that mints the coins on the network
pub async fn mint_coins(
    client: &HttpClient,
    args: MintCoinArgs,
) -> anyhow::Result<()> {
    log::debug!("The args are:: {:?}", args);

    let mut transaction: griffin_core::types::Transaction = Transaction {
        inputs: Vec::new(),
        outputs: vec![Output {
            payload: args.amount,
            owner: args.owner,
        }],
    };
  
    // The input appears as a new output.
    let utxo = fetch_storage(&args.input, client).await?;
    transaction.inputs.push(Input {
        output_ref: args.input.clone(),
    });
    transaction.outputs.push(utxo);
    
    let encoded_tx = hex::encode(transaction.encode());
    let params = rpc_params![encoded_tx];
    let spawn_response: Result<String, _> = client.request("author_submitExtrinsic", params).await;

    log::info!(
        "Node's response to mint-coin transaction: {:?}",
        spawn_response
    );

    let minted_coin_ref = OutputRef {
        tx_hash: <BlakeTwo256 as Hash>::hash_of(&transaction.encode()),
        index: 0,
    };
    let output = &transaction.outputs[0];
    let amount = output.payload;
    println!(
        "Minted {:?} worth {amount}. ",
        hex::encode(minted_coin_ref.encode())
    );

    Ok(())
}

/// Create and send a transaction that spends coins on the network
pub async fn spend_coins(
    db: &Db,
    client: &HttpClient,
    _keystore: &LocalKeystore,
    args: SpendArgs,
) -> anyhow::Result<()> {
    log::debug!("The args are:: {:?}", args);

    // Construct a template Transaction to push coins into later
    let mut transaction: Transaction = Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
    };

    // Construct each output and then push to the transaction
    let mut total_output_amount: u64 = 0;
    for amount in &args.output_amount {
        let output = Output {
            payload: *amount,
            owner: args.recipient,
        };
        total_output_amount += *amount;
        transaction.outputs.push(output);
    }

    // The total input set will consist of any manually chosen inputs
    // plus any automatically chosen to make the input amount high enough
    let mut total_input_amount: u64 = 0;
    for output_ref in &args.input {
        let (_owner_pubkey, amount) = sync::get_unspent(db, output_ref)?.ok_or(anyhow!(
            "user-specified output ref not found in local database"
        ))?;
        total_input_amount += amount;
    }

    // If the supplied inputs are not valuable enough to cover the output amount
    // we select the rest arbitrarily from the local db. (In many cases, this will be all the inputs.)
    if total_input_amount < total_output_amount {
        Err(anyhow!("Inputs not enough for given outputs."))?;
    }

    // Make sure each input decodes and is still present in the node's storage,
    // and then push to transaction.
    for output_ref in &args.input {
        get_coin_from_storage(output_ref, client).await?;
        transaction.inputs.push(Input {
            output_ref: output_ref.clone(),
        });
    }

    log::debug!("signed transactions is: {:#?}", transaction);

    // Send the transaction
    let genesis_spend_hex = hex::encode(transaction.encode());
    let params = rpc_params![genesis_spend_hex];
    let genesis_spend_response: Result<String, _> =
        client.request("author_submitExtrinsic", params).await;
    log::info!(
        "Node's response to spend transaction: {:?}",
        genesis_spend_response
    );

    // Print new output refs for user to check later
    let tx_hash = <BlakeTwo256 as Hash>::hash_of(&transaction.encode());
    for (i, output) in transaction.outputs.iter().enumerate() {
        let new_coin_ref = OutputRef {
            tx_hash,
            index: i as u32,
        };
        let amount = output.payload;

        println!(
            "Created {:?} worth {amount}. ",
            hex::encode(new_coin_ref.encode())
        );
    }

    Ok(())
}

/// Given an output ref, fetch the details about this coin from the node's
/// storage.
pub async fn get_coin_from_storage(
    output_ref: &OutputRef,
    client: &HttpClient,
) -> anyhow::Result<Coin> {
    let utxo = fetch_storage(output_ref, client).await?;
    let coin_in_storage: Coin = utxo.payload;

    Ok(coin_in_storage)
}

/// Apply a transaction to the local database, storing the new coins.
pub(crate) fn apply_transaction(
    db: &Db,
    tx_hash: <BlakeTwo256 as Hash>::Output,
    index: u32,
    output: &Output,
) -> anyhow::Result<()> {
    let amount = output.payload;
    let output_ref = OutputRef { tx_hash, index };
    let owner_pubkey = output.owner;
    crate::sync::add_unspent_output(db, &output_ref, &owner_pubkey, &amount)
}
