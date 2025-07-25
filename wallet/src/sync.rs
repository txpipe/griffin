//! This module is responsible for maintaining the wallet's local database of blocks
//! and owned UTxOs to the canonical database reported by the node.
//!
//! It is backed by a sled database
//!
//! ## Scheme
//!
//! There are 4 tables in the database:
//!
//! - BlockHashes     `block_number:u32` => `block_hash:H256`
//! - Blocks          `block_hash:H256` => `block:Block`
//! - UnspentOutputs  `input` => `(owner_pubkey, amount, datum_option)`
//! - SpentOutputs    `input` => `(owner_pubkey, amount, datum_option)`

use std::path::PathBuf;

use crate::order_book::{OrderDatum, ORDER_SCRIPT_HEX};
use crate::rpc;
use anyhow::anyhow;
use colored::Colorize;
use griffin_core::types::{
    compute_plutus_v2_script_hash, Address, Datum, Input, OpaqueBlock, PlutusScript, Transaction,
    Value,
};
use jsonrpsee::http_client::HttpClient;
use parity_scale_codec::{Decode, Encode};
use sled::Db;
use sp_core::H256;
use sp_runtime::{
    traits::{BlakeTwo256, Hash},
    OpaqueExtrinsic,
};

/// The identifier for the blocks tree in the db.
const BLOCKS: &str = "blocks";

/// The identifier for the block_hashes tree in the db.
const BLOCK_HASHES: &str = "block_hashes";

/// The identifier for the unspent tree in the db.
const UNSPENT: &str = "unspent";

/// The identifier for the spent tree in the db.
const SPENT: &str = "spent";

/// Open a database at the given location intended for the given genesis block.
///
/// If the database is already populated, make sure it is based on the expected genesis
/// If an empty database is opened, it is initialized with the expected genesis hash and genesis block
pub(crate) fn open_db(
    db_path: PathBuf,
    expected_genesis_hash: H256,
    expected_genesis_block: OpaqueBlock,
) -> anyhow::Result<Db> {
    // Error messages
    const DIFF_GEN: &str = "Node reports a different genesis block than wallet.";
    const ABORTING: &str = "Aborting all operations.";
    const HINT: &str = "HINT: Try removing the wallet DB by using the `--purge-db` option.";

    let db = sled::open(db_path.clone())?;

    // Open the tables we'll need
    let wallet_block_hashes_tree = db.open_tree(BLOCK_HASHES)?;
    let wallet_blocks_tree = db.open_tree("blocks")?;

    // If the database is already populated, just make sure it is for the same genesis block
    if height(&db)?.is_some() {
        // There are database blocks, so do a quick precheck to make sure they use the same genesis block.
        let wallet_genesis_ivec = wallet_block_hashes_tree
            .get(0.encode())?
            .expect("We know there are some blocks, so there should be a 0th block.");
        let wallet_genesis_hash = H256::decode(&mut &wallet_genesis_ivec[..])?;
        log::debug!("Found existing database.");
        if expected_genesis_hash != wallet_genesis_hash {
            log::error!("Wallet's genesis does not match expected. Aborting database opening.");
            return Err(anyhow!(
                "{DIFF_GEN}\nWallet: {:?}. Expected: {:?}.\n{}\n{}",
                wallet_genesis_hash,
                expected_genesis_hash,
                ABORTING,
                HINT,
            ));
        }
        return Ok(db);
    }

    // If there are no local blocks yet, initialize the tables
    log::info!(
        "Initializing fresh sync from genesis {:?}",
        expected_genesis_hash
    );

    // Update both tables
    wallet_block_hashes_tree.insert(0u32.encode(), expected_genesis_hash.encode())?;
    wallet_blocks_tree.insert(
        expected_genesis_hash.encode(),
        expected_genesis_block.encode(),
    )?;

    Ok(db)
}

pub(crate) async fn synchronize(db: &Db, client: &HttpClient) -> anyhow::Result<()> {
    synchronize_helper(db, client).await
}

/// Synchronize the local database to the database of the running node.
/// The wallet entirely trusts the data the node feeds it. In the bigger
/// picture, that means run your own (light) node.
pub(crate) async fn synchronize_helper(db: &Db, client: &HttpClient) -> anyhow::Result<()> {
    log::debug!("Synchronizing wallet with node.");

    // Start the algorithm at the height that the wallet currently thinks is best.
    // Fetch the block hash at that height from both the wallet's local db and the node
    let mut height: u32 = height(db)?.ok_or(anyhow!("tried to sync an uninitialized database"))?;
    let mut wallet_hash = get_block_hash(db, height)?
        .expect("Local database should have a block hash at the height reported as best");
    let mut node_hash: Option<H256> = rpc::node_get_block_hash(height, client).await?;

    // There may have been a re-org since the last time the node synced. So we loop backwards from the
    // best height the wallet knows about checking whether the wallet knows the same block as the node.
    // If not, we roll this block back on the wallet's local db, and then check the next ancestor.
    // When the wallet and the node agree on the best block, the wallet can re-sync following the node.
    // In the best case, where there is no re-org, this loop will execute zero times.
    while Some(wallet_hash) != node_hash {
        log::debug!("Divergence at height {height}. Node reports block: {node_hash:?}. Reverting wallet block: {wallet_hash:?}.");

        unapply_highest_block(db).await?;

        // Update for the next iteration
        height -= 1;
        wallet_hash = get_block_hash(db, height)?
            .expect("Local database should have a block hash at the height reported as best");
        node_hash = rpc::node_get_block_hash(height, client).await?;
    }

    // Orphaned blocks (if any) have been discarded at this point.
    // So we prepare our variables for forward syncing.
    log::debug!("Resyncing from common ancestor {node_hash:?} - {wallet_hash:?}");
    height += 1;
    node_hash = rpc::node_get_block_hash(height, client).await?;

    // Now that we have checked for reorgs and rolled back any orphan blocks, we can go ahead and sync forward.
    while let Some(hash) = node_hash {
        log::debug!("Forward syncing height {height}, hash {hash:?}");

        // Fetch the entire block in order to apply its transactions
        let block = rpc::node_get_block(hash, client)
            .await?
            .expect("Node should be able to return a block whose hash it already returned");

        // Apply the new block
        apply_block(db, block, hash).await?;

        height += 1;

        node_hash = rpc::node_get_block_hash(height, client).await?;
    }

    log::debug!("Done with forward sync up to {}", height - 1);

    Ok(())
}

/// Gets the owner and amount associated with an input from the unspent table
///
/// Some if the input exists, None if it doesn't
pub(crate) fn get_unspent(
    db: &Db,
    input: &Input,
) -> anyhow::Result<Option<(Address, Value, Option<Datum>)>> {
    let wallet_unspent_tree = db.open_tree(UNSPENT)?;
    let Some(ivec) = wallet_unspent_tree.get(input.encode())? else {
        return Ok(None);
    };

    Ok(Some(
        <(Address, Value, std::option::Option<Datum>)>::decode(&mut &ivec[..])?,
    ))
}

/// Gets the block hash from the local database given a block height. Similar the Node's RPC.
///
/// Some if the block exists, None if the block does not exist.
pub(crate) fn get_block_hash(db: &Db, height: u32) -> anyhow::Result<Option<H256>> {
    let wallet_block_hashes_tree = db.open_tree(BLOCK_HASHES)?;
    let Some(ivec) = wallet_block_hashes_tree.get(height.encode())? else {
        return Ok(None);
    };

    let hash = H256::decode(&mut &ivec[..])?;

    Ok(Some(hash))
}

/// Apply a block to the local database
pub(crate) async fn apply_block(db: &Db, b: OpaqueBlock, block_hash: H256) -> anyhow::Result<()> {
    log::debug!("Applying Block {:?}, Block_Hash {:?}", b, block_hash);
    // Write the hash to the block_hashes table
    let wallet_block_hashes_tree = db.open_tree(BLOCK_HASHES)?;
    wallet_block_hashes_tree.insert(b.header.number.encode(), block_hash.encode())?;

    // Write the block to the blocks table
    let wallet_blocks_tree = db.open_tree(BLOCKS)?;
    wallet_blocks_tree.insert(block_hash.encode(), b.encode())?;

    // Iterate through each transaction
    for tx in b.extrinsics {
        apply_transaction(db, tx).await?;
    }

    Ok(())
}

/// Apply a single transaction to the local database
/// The owner-specific tables are mappings from inputs to coin amounts
async fn apply_transaction(db: &Db, opaque_tx: OpaqueExtrinsic) -> anyhow::Result<()> {
    let encoded_extrinsic = opaque_tx.encode();
    let tx_hash = BlakeTwo256::hash_of(&encoded_extrinsic);
    log::debug!("syncing transaction {tx_hash:?}");

    // Now get a structured transaction
    let tx = <Transaction>::decode(&mut &encoded_extrinsic[..])?;

    // Insert all new outputs
    for (index, output) in tx.transaction_body.outputs.iter().enumerate() {
        let input = Input {
            tx_hash,
            index: index as u32,
        };

        crate::sync::add_unspent_output(
            db,
            &input,
            &output.address,
            &output.value,
            &output.datum_option,
        )?;
    }

    log::debug!("about to spend all inputs");
    // Spend all the inputs
    for input in tx.transaction_body.inputs {
        spend_output(db, &input)?;
    }

    Ok(())
}

/// Add a new output to the database updating all tables.
pub(crate) fn add_unspent_output(
    db: &Db,
    input: &Input,
    owner_pubkey: &Address,
    amount: &Value,
    datum_option: &Option<Datum>,
) -> anyhow::Result<()> {
    let unspent_tree = db.open_tree(UNSPENT)?;
    unspent_tree.insert(
        input.encode(),
        (owner_pubkey, amount, datum_option).encode(),
    )?;

    Ok(())
}

/// Remove an output from the database updating all tables.
fn remove_unspent_output(db: &Db, input: &Input) -> anyhow::Result<()> {
    let unspent_tree = db.open_tree(UNSPENT)?;

    unspent_tree.remove(input.encode())?;

    Ok(())
}

/// Mark an existing output as spent. This does not purge all record of the output from the db.
/// It just moves the record from the unspent table to the spent table
fn spend_output(db: &Db, input: &Input) -> anyhow::Result<()> {
    let unspent_tree = db.open_tree(UNSPENT)?;
    let spent_tree = db.open_tree(SPENT)?;

    let Some(ivec) = unspent_tree.remove(input.encode())? else {
        return Ok(());
    };
    let (owner, amount, datum_option) = <(Address, Value, Option<Datum>)>::decode(&mut &ivec[..])?;
    spent_tree.insert(input.encode(), (owner, amount, datum_option).encode())?;

    Ok(())
}

/// Mark an output that was previously spent back as unspent.
fn unspend_output(db: &Db, input: &Input) -> anyhow::Result<()> {
    let unspent_tree = db.open_tree(UNSPENT)?;
    let spent_tree = db.open_tree(SPENT)?;

    let Some(ivec) = spent_tree.remove(input.encode())? else {
        return Ok(());
    };
    let (owner, amount, datum_option) = <(Address, Value, Option<Datum>)>::decode(&mut &ivec[..])?;
    unspent_tree.insert(input.encode(), (owner, amount, datum_option).encode())?;

    Ok(())
}

/// Run a transaction backwards against a database. Mark all of the Inputs
/// as unspent, and drop all of the outputs.
fn unapply_transaction(db: &Db, tx: &OpaqueExtrinsic) -> anyhow::Result<()> {
    // We need to decode the opaque extrinsics. So we do a scale round-trip.
    let tx = <Transaction>::decode(&mut &tx.encode()[..])?;

    // Loop through the inputs moving each from spent to unspent
    for input in &tx.transaction_body.inputs {
        unspend_output(db, input)?;
    }

    // Loop through the outputs pruning them from unspent and dropping all record
    let tx_hash = BlakeTwo256::hash_of(&tx.encode());

    for i in 0..tx.transaction_body.outputs.len() {
        let input = Input {
            tx_hash,
            index: i as u32,
        };
        remove_unspent_output(db, &input)?;
    }

    Ok(())
}

/// Unapply the best block that the wallet currently knows about
pub(crate) async fn unapply_highest_block(db: &Db) -> anyhow::Result<()> {
    let wallet_blocks_tree = db.open_tree(BLOCKS)?;
    let wallet_block_hashes_tree = db.open_tree(BLOCK_HASHES)?;

    // Find the best height
    let height = height(db)?.ok_or(anyhow!("Cannot unapply block from uninitialized database"))?;

    // Take the hash from the block_hashes tables
    let Some(ivec) = wallet_block_hashes_tree.remove(height.encode())? else {
        return Err(anyhow!(
            "No block hash found at height reported as best. DB is inconsistent."
        ));
    };
    let hash = H256::decode(&mut &ivec[..])?;

    // Take the block from the blocks table
    let Some(ivec) = wallet_blocks_tree.remove(hash.encode())? else {
        return Err(anyhow!(
            "Block was not present in db but block hash was. DB is corrupted."
        ));
    };

    let block = OpaqueBlock::decode(&mut &ivec[..])?;

    // Loop through the transactions in reverse order calling unapply
    for tx in block.extrinsics.iter().rev() {
        unapply_transaction(db, tx)?;
    }

    Ok(())
}

/// Get the block height that the wallet is currently synced to
///
/// None means the db is not yet initialized with a genesis block
pub(crate) fn height(db: &Db) -> anyhow::Result<Option<u32>> {
    let wallet_block_hashes_tree = db.open_tree(BLOCK_HASHES)?;
    let num_blocks = wallet_block_hashes_tree.len();

    Ok(if num_blocks == 0 {
        None
    } else {
        Some(num_blocks as u32 - 1)
    })
}

/// Debugging use. Print the entire unspent outputs tree.
pub(crate) fn print_unspent_tree(db: &Db) -> anyhow::Result<()> {
    let wallet_unspent_tree = db.open_tree(UNSPENT)?;
    for x in wallet_unspent_tree.iter() {
        let (input_ivec, owner_amount_datum_ivec) = x?;
        let input = hex::encode(input_ivec);
        let (owner_pubkey, amount, datum_option) =
            <(Address, Value, Option<Datum>)>::decode(&mut &owner_amount_datum_ivec[..])?;
        let datum_option_hex = datum_option.map(|datum| hex::encode(datum.0));

        if owner_pubkey.to_string().starts_with("70") {
            println!(
                "{}:\n script address: {},\n datum: {:?},\n amount: {}",
                input.bold(),
                owner_pubkey.to_string().red(),
                datum_option_hex,
                amount.normalize(),
            );
        } else {
            println!(
                "{}:\n wallet address: {},\n datum: {:?},\n amount: {}",
                input.bold(),
                owner_pubkey.to_string().green(),
                datum_option_hex,
                amount.normalize(),
            );
        }
    }

    Ok(())
}

/// Print the available orders.
pub(crate) fn print_orders(db: &Db) -> anyhow::Result<()> {
    let wallet_unspent_tree = db.open_tree(UNSPENT)?;
    for x in wallet_unspent_tree.iter() {
        let (input_ivec, owner_amount_datum_ivec) = x?;
        let input = hex::encode(input_ivec);
        let (owner_pubkey, value, datum_option) =
            <(Address, Value, Option<Datum>)>::decode(&mut &owner_amount_datum_ivec[..])?;

        let script = PlutusScript(hex::decode(ORDER_SCRIPT_HEX).unwrap());
        let script_hash = compute_plutus_v2_script_hash(script.clone());
        let order_address =
            Address(hex::decode("70".to_owned() + &hex::encode(script_hash)).unwrap());

        if owner_pubkey == order_address {
            let order_datum = datum_option.map(|d| OrderDatum::from(d));
            match order_datum {
                None | Some(OrderDatum::MalformedOrderDatum) => {
                    println!(
                        "{}: datum {:?}, value: {}",
                        input,
                        order_datum,
                        value.normalize(),
                    );
                }
                Some(OrderDatum::Ok {
                    sender_payment_hash,
                    control_token_class,
                    ordered_class,
                    ordered_amount,
                }) => {
                    println!(
                        "{}:\n SENDER_PH: {:?}\n ORDERED_CLASS: {:#?}\n ORDERED_AMOUNT: {}\n CONTROL_TOKEN_CLASS: {:#?}\n VALUE: {}",
                        input,
                        sender_payment_hash,
                        ordered_class,
                        ordered_amount,
                        control_token_class,
                        value.normalize(),
                    );
                }
            }
        }
    }

    Ok(())
}

/// Iterate the entire unspent set summing the values of the coins
/// on a per-address basis.
pub(crate) fn get_balances(db: &Db) -> anyhow::Result<impl Iterator<Item = (Address, Value)>> {
    let mut balances = std::collections::HashMap::<Address, Value>::new();

    let wallet_unspent_tree = db.open_tree(UNSPENT)?;

    for raw_data in wallet_unspent_tree.iter() {
        let (_, owner_amount_datum_ivec) = raw_data?;
        let (owner, amount, _) =
            <(Address, Value, Option<Datum>)>::decode(&mut &owner_amount_datum_ivec[..])?;

        balances
            .entry(owner)
            .and_modify(|old| *old += amount.clone())
            .and_modify(|old| *old = old.normalize())
            .or_insert(amount.normalize());
    }

    Ok(balances.into_iter())
}
