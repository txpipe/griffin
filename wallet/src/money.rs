//! Wallet features related to spending money and checking balances.

use crate::{cli::MintCoinArgs, cli::SpendArgs, rpc::fetch_storage, sync};

use anyhow::anyhow;
use jsonrpsee::{core::client::ClientT, http_client::HttpClient, rpc_params};
use parity_scale_codec::Encode;
use pallas_codec::minicbor::{
    encode,
};
use sc_keystore::LocalKeystore;
use sled::Db;
use sp_runtime::traits::{BlakeTwo256, Hash};
use griffin_core::{
    types::{Coin, Input, Output, Transaction},
};

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
    let amount = output.value;
    println!(
        "Minted {:?} worth {amount}. ",
        hex::encode(Encode::encode(&minted_coin_ref))
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
    let mut transaction = Transaction::from((Vec::new(), Vec::new()));

    // Construct each output and then push to the transaction
    let mut total_amount: u64 = 0;
    for amount in &args.amount {
        let output = Output::from((args.recipient.clone(), *amount));
        total_amount += *amount;
        transaction.transaction_body.outputs.push(output);
    }

    // The total input set will consist of any manually chosen inputs
    // plus any automatically chosen to make the input amount high enough
    let mut total_input_amount: u64 = 0;
    for input in &args.input {
        let (_owner_pubkey, amount, _) = sync::get_unspent(db, input)?.ok_or(anyhow!(
            "user-specified output ref not found in local database"
        ))?;
        total_input_amount += amount;
    }

    // If the supplied inputs are not valuable enough to cover the output amount
    // we select the rest arbitrarily from the local db. (In many cases, this will be all the inputs.)
    if total_input_amount < total_amount {
        Err(anyhow!("Inputs not enough for given outputs."))?;
    }

    // Make sure each input decodes and is still present in the node's storage,
    // and then push to transaction.
    for input in &args.input {
        get_coin_from_storage(input, client).await?;
        transaction.transaction_body.inputs.push(input.clone());
    }

    log::debug!("signed transactions is: {:#?}", transaction);

    let mut tx_encoded: Vec<u8> = Vec::new();
    let _ = encode(&transaction, &mut tx_encoded);
    log::debug!("CBOR of Tx is: {}", hex::encode(tx_encoded));
    
    tx_encoded = Vec::new();
    let _ = encode(
        &pallas_primitives::babbage::Tx::from(transaction.clone()),
        &mut tx_encoded
    );
    log::debug!(
        "CBOR of Tx converted to Babbage is: {}",
        hex::encode(tx_encoded)
    );

    // Send the transaction
    let genesis_spend_hex = hex::encode(Encode::encode(&transaction));
    let params = rpc_params![genesis_spend_hex];
    let genesis_spend_response: Result<String, _> =
        client.request("author_submitExtrinsic", params).await;
    log::info!(
        "Node's response to spend transaction: {:?}",
        genesis_spend_response
    );

    // Print new output refs for user to check later
    let tx_hash = <BlakeTwo256 as Hash>::hash_of(&Encode::encode(&transaction));
    for (i, output) in transaction.transaction_body.outputs.iter().enumerate() {
        let new_coin_ref = Input {
            tx_hash,
            index: i as u32,
        };
        let amount = output.value;

        println!(
            "Created {:?} worth {amount}. ",
            hex::encode(Encode::encode(&new_coin_ref))
        );
    }

    Ok(())
}

/// Given an output ref, fetch the details about this coin from the node's
/// storage.
pub async fn get_coin_from_storage(
    input: &Input,
    client: &HttpClient,
) -> anyhow::Result<Coin> {
    let utxo = fetch_storage(input, client).await?;
    let coin_in_storage: Coin = utxo.value;

    Ok(coin_in_storage)
}

/// Apply a transaction to the local database, storing the new coins.
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
