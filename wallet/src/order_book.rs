//! Wallet features related to interacting with an order book.

use crate::{
    cli::{CancelOrderArgs, ResolveOrderArgs, StartOrderArgs},
    sync,
};
use anyhow::anyhow;
use griffin_core::{
    checks_interface::{babbage_minted_tx_from_cbor, babbage_tx_to_cbor, MIN_COIN_PER_OUTPUT},
    genesis::SHAWN_ADDRESS,
    pallas_codec::utils::MaybeIndefArray::Def,
    pallas_primitives::babbage::{
        Constr, MintedTx, PlutusData as PallasPlutusData, Tx as PallasTransaction,
    },
    pallas_traverse::OriginalHash,
    types::{
        address_from_hex, value_leq, Address, AssetName, Datum, ExUnits, Input, OrderDatum, Output,
        PlutusData, PlutusScript, Redeemer, RedeemerTag, Transaction, VKeyWitness, Value,
    },
};
use jsonrpsee::{core::client::ClientT, http_client::HttpClient, rpc_params};
use parity_scale_codec::Encode;
use sc_keystore::LocalKeystore;
use sled::Db;
use sp_core::ed25519::Public;
use sp_runtime::traits::{BlakeTwo256, Hash};
use std::vec;

pub const ORDER_SCRIPT_HEX: &str = "59036a01000032323232323232232322322533300732533300830063009375400826464a66601a6020004266e3c004dd7180198061baa3003300c37540122c6eb8c038004dd618069807180718071807180718071807180718051baa3001300a3754004264646464646464a66601e66ebcc020c044dd5003180399809980399809980418089baa30083011375401c97ae0330134c103d87a80004bd7008008a50533300e3375e600c66024602600666024602600497ae0300730103754600860206ea8c01cc040dd5006899b89375a600860206ea8c010c040dd5180398081baa00d00114a06eb4c048c04c004c048004c94ccc030cdc79bae3005300e3754600a601c6ea8c008c038dd5180298071baa00b488100132325333011301400213233013301400233013301400133013301430150014bd70180a0008b1bac3012001300137566004601c6ea800c4c8c94ccc044c0500084c8cc04cc050008cc04cc050004cc04cc050c0540052f5c060280022c6eb0c048004c004c8cc004004dd5980198079baa00422533301100114bd6f7b630099191919299980919b8f489000021003133016337606ea4008dd3000998030030019bab3013003375c6022004602a00460260024646600200200444a666022002297ae01323332223233001001003225333017001100313233019374e660326ea4018cc064dd49bae30160013301937506eb4c05c0052f5c066006006603600460320026eb8c040004dd5980880099801801980a8011809800918081808800992999805180418059baa0011300f300c37540022c64a66601a0022980103d87a8000130023300e300f0014bd701bac300e300f300f300b3754600460166ea800cdd2a40004601a00229309b2b19299980318020008a99980498041baa00214985854ccc018cdc3a40040022a66601260106ea8008526161630063754002a666006600260086ea80084c8c94ccc020c02c0084c9265333005300330063754002264646464a666018601e004264932999804980398051baa001132323232533301030130021324994ccc034c02cc038dd5001899191919299980a180b8010a4c2c6eb8c054004c054008dd7180980098079baa0031616375a60220026022004601e00260166ea80045858c034004c034008dd7180580098039baa00116163009001300537540042c6e1d20005734aae7555cf2ab9f5740ae855d11";

pub const ORDER_ADDRESS_HEX: &str = "70b4dcdce0cc9e1ecbc4f16cf14e2e15e189b6c05d48f69ffdfac34395";

pub async fn start_order(
    db: &Db,
    client: &HttpClient,
    keystore: &LocalKeystore,
    args: StartOrderArgs,
) -> anyhow::Result<()> {
    log::debug!("The args are:: {:?}", args);

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

    let order_value: Value = Value::from((
        args.sent_policy,
        <AssetName>::from(args.sent_name),
        args.sent_amount,
    )) + Value::Coin(MIN_COIN_PER_OUTPUT);
    let order_address = Address(hex::decode(ORDER_ADDRESS_HEX).unwrap());

    let order_datum: Datum = <_>::from(OrderDatum::Ok {
        sender_payment_hash: args.sender_ph,
        policy_id: args.ordered_policy,
        asset_name: AssetName::from(args.ordered_name),
        amount: args.ordered_amount,
    });

    // Construct the output and then push to the transaction
    let order_output = Output::from((order_address, order_value.clone(), order_datum));
    transaction.transaction_body.outputs.push(order_output);

    // If the supplied inputs surpass output amount, we redirect the rest to Shawn
    if value_leq(&order_value, &input_value) {
        let remainder: Value = input_value - order_value;
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

pub async fn resolve_order(
    db: &Db,
    client: &HttpClient,
    keystore: &LocalKeystore,
    args: ResolveOrderArgs,
) -> anyhow::Result<()> {
    log::debug!("The args are:: {:?}", args);

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

    if let Some((_, order_value, datum_option)) = sync::get_unspent(db, &args.order_input)? {
        input_value += order_value;

        if datum_option == None {
            Err(anyhow!("No order datum"))?;
        }
        let order_datum = OrderDatum::from(datum_option.unwrap());

        match order_datum {
            OrderDatum::MalformedOrderDatum => Err(anyhow!("Malformed order datum"))?,
            OrderDatum::Ok {
                sender_payment_hash,
                policy_id,
                asset_name,
                amount: _,
            } => {
                let sender_ph = hex::encode(sender_payment_hash.0);

                let sender_address: Address =
                    Address(hex::decode("61".to_owned() + &sender_ph).unwrap());

                let payment_value: Value = Value::from((policy_id, asset_name, args.paid_amount))
                    + Value::Coin(MIN_COIN_PER_OUTPUT);

                // Construct the output and then push to the transaction
                let payment_output = Output::from((sender_address, payment_value.clone()));
                transaction.transaction_body.outputs.push(payment_output);

                // If the supplied inputs surpass output amount, we redirect the rest to Shawn
                if value_leq(&payment_value, &input_value) {
                    let remainder: Value = input_value - payment_value;
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
                transaction.transaction_body.inputs.push(args.order_input);

                let order_script = hex::decode(ORDER_SCRIPT_HEX).unwrap();
                let resolve_redeemer = Redeemer {
                    tag: RedeemerTag::Spend,
                    index: 0,
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
                transaction.transaction_body.required_signers = Some(vec![sender_payment_hash]);
                transaction.transaction_body.validity_interval_start = Some(82651727);

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
                transaction.transaction_witness_set.redeemer = Some(vec![resolve_redeemer]);
                transaction.transaction_witness_set.plutus_script =
                    Some(vec![PlutusScript(order_script)]);

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
            }
        }
    } else {
        Err(anyhow!(
            "User-specified order utxo {:x?} not found in wallet database",
            &args.order_input,
        ))?
    }
}

pub async fn cancel_order(
    db: &Db,
    client: &HttpClient,
    keystore: &LocalKeystore,
    args: CancelOrderArgs,
) -> anyhow::Result<()> {
    log::debug!("The args are:: {:?}", args);

    // Construct a template Transaction to push coins into later
    let mut transaction = Transaction::from((Vec::new(), Vec::new()));

    if let Some((_, order_value, datum_option)) = sync::get_unspent(db, &args.order_input)? {
        if datum_option == None {
            Err(anyhow!("No order datum"))?;
        }
        let order_datum = OrderDatum::from(datum_option.unwrap());

        match order_datum {
            OrderDatum::MalformedOrderDatum => Err(anyhow!("Malformed order datum"))?,
            OrderDatum::Ok {
                sender_payment_hash,
                policy_id: _,
                asset_name: _,
                amount: _,
            } => {
                // Construct the output and then push to the transaction
                let output = Output::from((address_from_hex(SHAWN_ADDRESS), order_value));
                transaction.transaction_body.outputs.push(output);
                transaction.transaction_body.inputs.push(args.order_input);

                let order_script = hex::decode(ORDER_SCRIPT_HEX).unwrap();
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

                transaction.transaction_body.required_signers = Some(vec![sender_payment_hash]);
                transaction.transaction_body.validity_interval_start = Some(82651727);

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
                transaction.transaction_witness_set.redeemer = Some(vec![cancel_redeemer]);
                transaction.transaction_witness_set.plutus_script =
                    Some(vec![PlutusScript(order_script)]);

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
            }
        }
    } else {
        Err(anyhow!(
            "User-specified order utxo {:x?} not found in wallet database",
            &args.order_input,
        ))?
    }
}
