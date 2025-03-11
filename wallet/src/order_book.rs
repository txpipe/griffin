//! Wallet features related to interacting with an order book.

use crate::{
    cli::{CancelOrderArgs, ResolveOrderArgs, StartOrderArgs},
    sync,
};
use anyhow::anyhow;
use griffin_core::{
    checks_interface::{babbage_minted_tx_from_cbor, babbage_tx_to_cbor, MIN_COIN_PER_OUTPUT},
    genesis::SHAWN_ADDRESS,
    h224::H224,
    pallas_codec::minicbor,
    pallas_codec::utils::{
        Int,
        MaybeIndefArray::{Def, Indef},
    },
    pallas_crypto::hash::Hash as PallasHash,
    pallas_primitives::babbage::{
        BigInt, BoundedBytes, Constr, MintedTx, PlutusData as PallasPlutusData,
        Tx as PallasTransaction,
    },
    pallas_traverse::OriginalHash,
    types::{
        address_from_hex, compute_plutus_v2_script_hash, Address, AssetClass, AssetName, Coin,
        Datum, ExUnits, Input, Multiasset, Output, PlutusData, PlutusScript, Redeemer, RedeemerTag,
        Transaction, VKeyWitness, Value,
    },
};
use jsonrpsee::{core::client::ClientT, http_client::HttpClient, rpc_params};
use parity_scale_codec::Encode;
use sc_keystore::LocalKeystore;
use sled::Db;
use sp_core::ed25519::Public;
use sp_runtime::traits::{BlakeTwo256, Hash};
use std::vec;

pub const ORDER_SCRIPT_HEX: &str = "59080c010000323232323232322253232323330063001300737540082a66600c646464646464a66601866e1c005200114a2264646464a666026602c004264646464646464a66602ea66602e60260182a66602e60146eb8c044c064dd5002899b8f00d375c600660326ea80145280a501533301700415333017001100214a0294052819b8848000dd69801180c1baa30023018375400a66e1cc94ccc058c048c05cdd50008a400026eb4c06cc060dd500099299980b1809180b9baa00114c0103d87a8000132330010013756603860326ea8008894ccc06c004530103d87a80001323232533301b3371e0226eb8c07000c4c060cc07cdd4000a5eb804cc014014008dd6980e001180f801180e80099198008009bab30023018375400e44a666034002298103d87a80001323232533301a300d375c60360062602e6603c6e980052f5c026600a00a0046eacc06c008c078008c0700040288c068c06c004cc88c8cc00400400c894ccc068004528099299980c19b8f375c603a00400829444cc00c00c004c074004dd6180c180c980c980c980c980c980c980c980c980a9baa300d301537540226eb8c034c054dd5001180b980c001180b00098091baa332253330123370e900218099baa001132325333017301a0021320025333014300f30153754002264646464a666036603c00426464931804801299980c1809980c9baa003132323232533301f30220021324994ccc070c05cc074dd50008991919192999811981300109924c60200062c6eb4c090004c090008c088004c078dd50008b0b181000098100011bae301e001301a37540062c2c603800260380046034002602c6ea80045858c060004c050dd50008b12999808980618091baa0011323232325333018301b002149858dd7180c800980c8011bae3017001301337540022c600860246ea800458c050004c8cc004004dd6180198089baa30093011375401a44a666026002297ae0132325333012325333013300f301437540022600c6eb8c060c054dd50008a50300c30143754601860286ea80084cc058008cc0100100044cc010010004c05c008c054004dc780291809180998098009bad30103011002375c601e002601e0046eb8c034004c8c94ccc030c03c008400458dd61806800991980080099198008009bab300e300f300f300f300f300b3754600660166ea801c894ccc03400452f5bded8c0264646464a66601c66e3d2201000021003133012337606ea4008dd3000998030030019bab300f003375c601a0046022004601e00244a666018002297ae01323332223233001001003225333012001100313233014374e660286ea4018cc050dd49bae30110013301437506eb4c0480052f5c066006006602c00460280026eb8c02c004dd598060009980180198080011807000918060008a4c26cac26644644a666014646464646464646464a666026a666026601c60286ea80304c8c94ccc060c06c0084cdc78009bae300b301737546016602e6ea805058dd7180c8009bac301830193019301930193019301930193019301537546012602a6ea80284c8c8c8c8c94ccc060cdd79807180d1baa00530153301c30153301c300e301a3754601c60346ea805d2f5c06603898103d87a80004bd7008008a5053330173375e602866036603800666036603800497ae0300d30193754600c60326ea8c034c064dd500b099b89375a600c60326ea8c018c064dd51806980c9baa01600114a06eb4c06cc070004c06c0054ccc050cdc79bae300a301637546014602c6ea8c00cc058dd51805180b1baa013488100132325333019301c0021323301b301c0023301b301c0013301b301c301d0014bd70180e0008b1bac301a001300937566006602c6ea80044c8c94ccc064c0700084c8cc06cc070008cc06cc070004cc06cc070c0740052f5c060380022c6eb0c068004c024cc020dd59801980b1baa001488100325333014300f3015375400226032602c6ea800458c94ccc05c004530103d87a8000130113301830190014bd701bac301830193019301537546012602a6ea80284004528299980919b87375a602e603000690008a99980919b8f004375c601060286ea8c004c050dd5008899b8f002375c600260286ea8c004c050dd50088a5014a04602e60300026eb8c054004c054008dd7180980099192999809180a80108008b1bac3013001300233001375660246026602660266026601e6ea8c00cc03cdd500224410022323300100100322533301300114bd6f7b630099191919299980a19b8f0070021003133018337606ea4008dd3000998030030019bab3015003375c6026004602e004602a0024646600200200444a666022002297ae01323332223233001001003225333017001100313233019374e660326ea4018cc064dd49bae30160013301937506eb4c05c0052f5c066006006603600460320026eb8c040004dd5980880099801801980a8011809800918080008a4c26cac64a66601260080022a66601860166ea8008526161533300930050011533300c300b37540042930b0b18049baa00132533300730023008375400c264646464a66601c6022004264649318030012999805980318061baa003132323232533301230150021324994ccc03cc028c040dd5000899191919299980b180c80109924c601a0062c6eb4c05c004c05c008c054004c044dd50008b0b180980098098011bae3011001300d37540062c2c601e002601e004601a00260126ea80185894ccc01cc008c020dd5000899191919299980718088010a4c2c6eb8c03c004c03c008dd7180680098049baa00116300b300837540086e1d2000370e90011ba5480015cd2ab9d5573caae7d5d02ba157441";

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OrderDatum {
    Ok {
        sender_payment_hash: H224,
        control_token_class: AssetClass,
        ordered_class: AssetClass,
        ordered_amount: Coin,
    },
    MalformedOrderDatum,
}

pub async fn start_order(
    db: &Db,
    client: &HttpClient,
    keystore: &LocalKeystore,
    args: StartOrderArgs,
) -> anyhow::Result<()> {
    log::debug!("The args are:: {:?}", args);

    let order_script = PlutusScript(hex::decode(ORDER_SCRIPT_HEX).unwrap());
    let control_token_policy = compute_plutus_v2_script_hash(order_script.clone());
    let control_token_name = AssetName::from("controlToken".to_string());
    let minted_value = Value::from((control_token_policy, control_token_name.clone(), 1));

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

    let order_value: Value = minted_value.clone()
        + Value::from((
            args.sent_policy,
            <AssetName>::from(args.sent_name.clone()),
            args.sent_amount,
        ))
        + Value::Coin(MIN_COIN_PER_OUTPUT);
    let order_address =
        Address(hex::decode("70".to_owned() + &hex::encode(control_token_policy)).unwrap());

    let order_datum: Datum = <_>::from(OrderDatum::Ok {
        sender_payment_hash: args.sender_ph,
        control_token_class: AssetClass {
            policy_id: control_token_policy,
            asset_name: control_token_name.clone(),
        },
        ordered_class: AssetClass {
            policy_id: args.ordered_policy,
            asset_name: AssetName::from(args.ordered_name),
        },
        ordered_amount: args.ordered_amount,
    });

    // Construct the output and then push to the transaction
    let order_output = Output::from((order_address, order_value.clone(), order_datum));
    transaction.transaction_body.outputs.push(order_output);

    // If the supplied inputs surpass output amount, we redirect the rest to Shawn
    let remainder: Value = minted_value + input_value - order_value;
    if !remainder.is_null() {
        println!("Note: Excess input amount goes to Shawn.");
        let output = Output::from((address_from_hex(SHAWN_ADDRESS), remainder));
        transaction.transaction_body.outputs.push(output);
    }

    // Push each input to the transaction.
    for input in &args.input {
        transaction.transaction_body.inputs.push(input.clone());
    }

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
    transaction.transaction_body.required_signers = Some(vec![args.sender_ph]);

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
    transaction.transaction_witness_set.plutus_script = Some(vec![order_script]);
    transaction.transaction_witness_set.redeemer = Some(vec![mint_redeemer]);

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

    let order_script = PlutusScript(hex::decode(ORDER_SCRIPT_HEX).unwrap());
    let control_token_policy = compute_plutus_v2_script_hash(order_script.clone());
    let control_token_name = AssetName::from("controlToken".to_string());
    let burnt_value = Value::from((control_token_policy, control_token_name.clone(), 1));

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
                control_token_class: _,
                ordered_class,
                ordered_amount: _,
            } => {
                let sender_ph = hex::encode(sender_payment_hash.0);

                let sender_address: Address =
                    Address(hex::decode("61".to_owned() + &sender_ph).unwrap());

                let payment_value: Value = Value::from((
                    ordered_class.policy_id,
                    ordered_class.asset_name,
                    args.paid_amount,
                )) + Value::Coin(MIN_COIN_PER_OUTPUT);

                // Construct the output and then push to the transaction
                let payment_output = Output::from((sender_address, payment_value.clone()));
                transaction.transaction_body.outputs.push(payment_output);

                // If the supplied inputs surpass output amount, we redirect the rest to Shawn
                let remainder: Value = input_value - payment_value - burnt_value;
                if !remainder.is_null() {
                    println!("Note: Excess input amount goes to Shawn.");
                    let output = Output::from((address_from_hex(SHAWN_ADDRESS), remainder));
                    transaction.transaction_body.outputs.push(output);
                }

                // Push each input to the transaction.
                for input in &args.input {
                    transaction.transaction_body.inputs.push(input.clone());
                }
                transaction.transaction_body.inputs.push(args.order_input);

                let resolve_redeemer = Redeemer {
                    tag: RedeemerTag::Spend,
                    index: 0,
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
                transaction.transaction_body.required_signers = Some(vec![sender_payment_hash]);

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
                transaction.transaction_witness_set.plutus_script = Some(vec![order_script]);
                transaction.transaction_witness_set.redeemer =
                    Some(vec![burn_redeemer, resolve_redeemer]);

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

    let order_script = PlutusScript(hex::decode(ORDER_SCRIPT_HEX).unwrap());
    let control_token_policy = compute_plutus_v2_script_hash(order_script.clone());
    let control_token_name = AssetName::from("controlToken".to_string());
    let burnt_value = Value::from((control_token_policy, control_token_name.clone(), 1));

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
                control_token_class: _,
                ordered_class: _,
                ordered_amount: _,
            } => {
                // Construct the output and then push to the transaction
                let output =
                    Output::from((address_from_hex(SHAWN_ADDRESS), order_value - burnt_value));
                transaction.transaction_body.outputs.push(output);
                transaction.transaction_body.inputs.push(args.order_input);

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
                transaction.transaction_body.required_signers = Some(vec![sender_payment_hash]);

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
                transaction.transaction_witness_set.redeemer =
                    Some(vec![burn_redeemer, cancel_redeemer]);
                transaction.transaction_witness_set.plutus_script = Some(vec![order_script]);

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

impl From<OrderDatum> for Datum {
    fn from(order_datum: OrderDatum) -> Self {
        Datum(PlutusData::from(PallasPlutusData::from(order_datum)).0)
    }
}

impl From<Datum> for OrderDatum {
    fn from(datum: Datum) -> Self {
        <_>::from(PallasPlutusData::from(PlutusData(datum.0)))
    }
}

impl From<OrderDatum> for PallasPlutusData {
    fn from(order_datum: OrderDatum) -> Self {
        match order_datum {
            OrderDatum::Ok {
                sender_payment_hash,
                control_token_class,
                ordered_class,
                ordered_amount,
            } => PallasPlutusData::Constr(Constr {
                tag: 121,
                any_constructor: None,
                fields: Indef(
                    [
                        PallasPlutusData::Constr(Constr {
                            tag: 121,
                            any_constructor: None,
                            fields: Indef(
                                [
                                    PallasPlutusData::BoundedBytes(BoundedBytes(
                                        sender_payment_hash.0.to_vec(),
                                    )),
                                    PallasPlutusData::Constr(Constr {
                                        tag: 121,
                                        any_constructor: None,
                                        fields: Indef(
                                            [
                                                PallasPlutusData::Constr(Constr {
                                                    tag: 121,
                                                    any_constructor: None,
                                                    fields: Indef(
                                                        [
                                                            PallasPlutusData::BoundedBytes(
                                                                BoundedBytes(
                                                                    ordered_class
                                                                        .policy_id
                                                                        .0
                                                                        .to_vec(),
                                                                ),
                                                            ),
                                                            PallasPlutusData::BoundedBytes(
                                                                BoundedBytes(
                                                                    ordered_class
                                                                        .asset_name
                                                                        .0
                                                                        .into(),
                                                                ),
                                                            ),
                                                        ]
                                                        .to_vec(),
                                                    ),
                                                }),
                                                PallasPlutusData::BigInt(BigInt::Int(Int(
                                                    minicbor::data::Int::from(ordered_amount),
                                                ))),
                                            ]
                                            .to_vec(),
                                        ),
                                    }),
                                ]
                                .to_vec(),
                            ),
                        }),
                        PallasPlutusData::Constr(Constr {
                            tag: 121,
                            any_constructor: None,
                            fields: Indef(
                                [
                                    PallasPlutusData::BoundedBytes(BoundedBytes(
                                        control_token_class.policy_id.0.to_vec(),
                                    )),
                                    PallasPlutusData::BoundedBytes(BoundedBytes(
                                        control_token_class.asset_name.0.into(),
                                    )),
                                ]
                                .to_vec(),
                            ),
                        }),
                    ]
                    .to_vec(),
                ),
            }),
            OrderDatum::MalformedOrderDatum => {
                PallasPlutusData::BigInt(BigInt::Int(Int(minicbor::data::Int::from(0))))
            }
        }
    }
}

impl From<PallasPlutusData> for OrderDatum {
    fn from(data: PallasPlutusData) -> Self {
        if let PallasPlutusData::Constr(Constr {
            tag: 121,
            any_constructor: None,
            fields: Indef(order_datum),
        }) = data
        {
            if let [PallasPlutusData::Constr(Constr {
                tag: 121,
                any_constructor: None,
                fields: Indef(order_info),
            }), PallasPlutusData::Constr(Constr {
                tag: 121,
                any_constructor: None,
                fields: Indef(control_token_class),
            })] = &order_datum[..]
            {
                if let [PallasPlutusData::BoundedBytes(BoundedBytes(sender_payment_hash_vec)), PallasPlutusData::Constr(Constr {
                    tag: 121,
                    any_constructor: None,
                    fields: Indef(asset_info),
                })] = &order_info[..]
                {
                    if let [PallasPlutusData::Constr(Constr {
                        tag: 121,
                        any_constructor: None,
                        fields: Indef(asset_class),
                    }), PallasPlutusData::BigInt(BigInt::Int(Int(amount)))] = &asset_info[..]
                    {
                        if let [PallasPlutusData::BoundedBytes(BoundedBytes(policy_id_vec)), PallasPlutusData::BoundedBytes(BoundedBytes(asset_name_vec))] =
                            &asset_class[..]
                        {
                            if let [PallasPlutusData::BoundedBytes(BoundedBytes(
                                control_token_policy_vec,
                            )), PallasPlutusData::BoundedBytes(BoundedBytes(
                                control_token_name_vec,
                            ))] = &control_token_class[..]
                            {
                                OrderDatum::Ok {
                                    sender_payment_hash: H224::from(PallasHash::from(
                                        sender_payment_hash_vec.as_slice(),
                                    )),
                                    control_token_class: AssetClass {
                                        policy_id: H224::from(PallasHash::from(
                                            control_token_policy_vec.as_slice(),
                                        )),
                                        asset_name: AssetName(
                                            String::from_utf8(control_token_name_vec.to_vec())
                                                .unwrap(),
                                        ),
                                    },
                                    ordered_class: AssetClass {
                                        policy_id: H224::from(PallasHash::from(
                                            policy_id_vec.as_slice(),
                                        )),
                                        asset_name: AssetName(
                                            String::from_utf8(asset_name_vec.to_vec()).unwrap(),
                                        ),
                                    },
                                    ordered_amount: TryFrom::<minicbor::data::Int>::try_from(
                                        *amount,
                                    )
                                    .unwrap(),
                                }
                            } else {
                                OrderDatum::MalformedOrderDatum
                            }
                        } else {
                            OrderDatum::MalformedOrderDatum
                        }
                    } else {
                        OrderDatum::MalformedOrderDatum
                    }
                } else {
                    OrderDatum::MalformedOrderDatum
                }
            } else {
                OrderDatum::MalformedOrderDatum
            }
        } else {
            OrderDatum::MalformedOrderDatum
        }
    }
}
