//! CLI wallet to demostrate spending and minting transactions.
//!
//! ## Basic usage
//!
//! In terminal, run the node in development mode:
//!
//! ```bash
//! ./target/release/griffin-solochain-node --dev
//! ```
//!
//! In another terminal, one can interact with the node by issuing wallet
//! commands. Every time the wallet starts (without the `--help` or `--version`
//! command-line options), it will try to synchronize its database with the
//! present chain state through RPC port 9944 (the [DEFAULT_ENDPOINT]), unless
//! there is a mismatch with the genesis hash.
//!
//! To list the whole UTxO set, run
//!
//! ```bash
//! ./target/release/griffin-wallet show-all-outputs
//! ```

extern crate alloc;

use alloc::{string::String, vec::Vec};
use clap::Parser;
use griffin_core::{
    h224::H224,
    pallas_crypto::hash::Hasher as PallasHasher,
    types::{Address, Input, Value},
};
use hex::FromHex;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use parity_scale_codec::{Decode, Encode};
use sp_core::H256;
use std::path::PathBuf;

mod cli;
mod command;
mod keystore;
mod order_book;
mod rpc;
mod sync;

use cli::{Cli, Command};

/// The default RPC endpoint for the wallet to connect to
const DEFAULT_ENDPOINT: &str = "http://localhost:9944";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Parse command line args
    let cli = Cli::parse();

    // If the user specified --tmp or --dev, then use a temporary directory.
    let tmp = cli.tmp || cli.dev;

    // Setup the data paths.
    let data_path = match tmp {
        true => temp_dir(),
        _ => cli.base_path.unwrap_or_else(default_data_path),
    };
    let keystore_path = data_path.join("keystore");
    let db_path = data_path.join("wallet_database");

    // Setup the keystore
    let keystore = sc_keystore::LocalKeystore::open(keystore_path.clone(), None)?;

    if cli.dev {
        // Insert the example Shawn key so example transactions can be signed.
        crate::keystore::insert_development_key_for_this_session(&keystore)?;
    }

    // Setup jsonrpsee and endpoint-related information.
    // https://github.com/paritytech/jsonrpsee/blob/master/examples/examples/http.rs
    let client = HttpClientBuilder::default().build(cli.endpoint)?;

    // Read node's genesis block.
    let node_genesis_hash = rpc::node_get_block_hash(0, &client)
        .await?
        .expect("node should be able to return some genesis hash");
    let node_genesis_block = rpc::node_get_block(node_genesis_hash, &client)
        .await?
        .expect("node should be able to return some genesis block");
    log::debug!("Node's Genesis block::{:?}", node_genesis_hash);

    if cli.purge_db {
        std::fs::remove_dir_all(db_path.clone()).map_err(|e| {
            log::warn!(
                "Unable to remove database directory at {}\nPlease remove it manually.",
                db_path.to_string_lossy()
            );
            e
        })?;
    }

    // Open the local database
    let db = sync::open_db(db_path, node_genesis_hash, node_genesis_block.clone())?;

    let num_blocks =
        sync::height(&db)?.expect("db should be initialized automatically when opening.");
    log::info!("Number of blocks in the db: {num_blocks}");

    if !sled::Db::was_recovered(&db) {
        sync::apply_block(&db, node_genesis_block, node_genesis_hash).await?;
    }

    // Synchronize the wallet with attached node unless instructed otherwise.
    if cli.no_sync {
        log::warn!("Skipping sync with node. Using previously synced information.")
    } else {
        sync::synchronize(&db, &client).await?;

        log::info!(
            "Wallet database synchronized with node to height {:?}",
            sync::height(&db)?.expect("We just synced, so there is a height available")
        );
    }

    // Dispatch to proper subcommand
    match cli.command {
        Some(Command::VerifyUtxo { input }) => {
            println!("Details of coin {}:", hex::encode(input.encode()));

            // Print the details from storage
            let coin_from_storage = get_coin_from_storage(&input, &client).await?;
            print!("Found in storage.  Value: {:?}, ", coin_from_storage);

            // Print the details from the local db
            match sync::get_unspent(&db, &input)? {
                Some((owner, amount, _)) => {
                    println!("Found in local db. Value: {amount:?}, owned by {owner}");
                }
                None => {
                    println!("Not found in local db");
                }
            }

            Ok(())
        }
        Some(cli::Command::SpendValue(args)) => {
            command::spend_value(&db, &client, &keystore, args).await
        }
        Some(Command::InsertKey { seed }) => crate::keystore::insert_key(&keystore, &seed),
        Some(Command::GenerateKey { password }) => {
            crate::keystore::generate_key(&keystore, password)?;
            Ok(())
        }
        Some(Command::ShowKeys) => {
            crate::keystore::get_keys(&keystore)?.for_each(|pubkey| {
                let pk_str: &str = &hex::encode(pubkey);
                let hash: String =
                    PallasHasher::<224>::hash(&<[u8; 32]>::from_hex(pk_str).unwrap()).to_string();
                println!("key: 0x{}; addr: 0x61{}", pk_str, hash);
            });

            Ok(())
        }
        Some(Command::RemoveKey { pub_key }) => {
            println!("CAUTION!!! About permanently remove {pub_key}. This action CANNOT BE REVERSED. Type \"proceed\" to confirm deletion.");

            let mut confirmation = String::new();
            std::io::stdin()
                .read_line(&mut confirmation)
                .expect("Failed to read line");

            if confirmation.trim() == "proceed" {
                crate::keystore::remove_key(&keystore_path, &pub_key)
            } else {
                println!("Deletion aborted. That was close.");
                Ok(())
            }
        }
        Some(Command::ShowBalance) => {
            println!("Balance Summary");
            let mut total = Value::Coin(0);
            let balances = sync::get_balances(&db)?;
            for (account, balance) in balances {
                total += balance.clone();
                println!("{account}: {balance}");
            }
            println!("{:-<58}", "");
            println!("Total:   {}", total.normalize());

            Ok(())
        }
        Some(Command::ShowAllOutputs) => {
            println!("###### Unspent outputs ###########");
            sync::print_unspent_tree(&db)?;
            println!("To see all details of a particular UTxO, invoke the `verify-utxo` command.");
            Ok(())
        }
        Some(Command::ShowAllOrders) => {
            println!("###### Available Orders ###########");
            sync::print_orders(&db)?;
            Ok(())
        }
        Some(cli::Command::BuildTx(args)) => command::build_tx(&db, &client, &keystore, args).await,
        None => {
            log::info!("No Wallet Command invoked. Exiting.");
            Ok(())
        }
    }?;

    if tmp {
        // Cleanup the temporary directory.
        std::fs::remove_dir_all(data_path.clone()).map_err(|e| {
            log::warn!(
                "Unable to remove temporary data directory at {}\nPlease remove it manually.",
                data_path.to_string_lossy()
            );
            e
        })?;
    }

    Ok(())
}

/// Parse a string into an H256 that represents a public key
pub(crate) fn h256_from_string(s: &str) -> anyhow::Result<H256> {
    let s = strip_0x_prefix(s);

    let mut bytes: [u8; 32] = [0; 32];
    hex::decode_to_slice(s, &mut bytes as &mut [u8])
        .map_err(|_| clap::Error::new(clap::error::ErrorKind::ValueValidation))?;
    Ok(H256::from(bytes))
}

/// Parse a string into an H224 that represents a policy ID.
pub(crate) fn h224_from_string(s: &str) -> anyhow::Result<H224> {
    let s = strip_0x_prefix(s);

    let mut bytes: [u8; 28] = [0; 28];
    hex::decode_to_slice(s, &mut bytes as &mut [u8])
        .map_err(|_| clap::Error::new(clap::error::ErrorKind::ValueValidation))?;
    Ok(H224::from(bytes))
}

/// Parse a string into an Address that represents a public key
pub(crate) fn address_from_string(s: &str) -> anyhow::Result<Address> {
    let s = strip_0x_prefix(s);

    let mut bytes: [u8; 29] = [0; 29];
    hex::decode_to_slice(s, &mut bytes as &mut [u8])
        .map_err(|_| clap::Error::new(clap::error::ErrorKind::ValueValidation))?;
    Ok(Address(Vec::from(bytes)))
}

/// Parse an output ref from a string
fn input_from_string(s: &str) -> Result<Input, clap::Error> {
    let s = strip_0x_prefix(s);
    let bytes =
        hex::decode(s).map_err(|_| clap::Error::new(clap::error::ErrorKind::ValueValidation))?;

    Input::decode(&mut &bytes[..])
        .map_err(|_| clap::Error::new(clap::error::ErrorKind::ValueValidation))
}

/// Takes a string and checks for a 0x prefix. Returns a string without a 0x prefix.
fn strip_0x_prefix(s: &str) -> &str {
    if &s[..2] == "0x" {
        &s[2..]
    } else {
        s
    }
}

/// Generate a plaform-specific temporary directory for the wallet
fn temp_dir() -> PathBuf {
    // Since it is only used for testing purpose, we don't need a secure temp dir, just a unique one.
    std::env::temp_dir().join(format!(
        "griffin-wallet-{}",
        std::time::UNIX_EPOCH.elapsed().unwrap().as_millis(),
    ))
}

/// Generate the platform-specific default data path for the wallet
fn default_data_path() -> PathBuf {
    // This uses the directories crate.
    // https://docs.rs/directories/latest/directories/struct.ProjectDirs.html

    // Application developers may want to put actual qualifiers or organization here
    let qualifier = "";
    let organization = "";
    let application = env!("CARGO_PKG_NAME");

    directories::ProjectDirs::from(qualifier, organization, application)
        .expect("app directories exist on all supported platforms; qed")
        .data_dir()
        .into()
}

/// Given an output ref, fetch the details about its value from the node's
/// storage.
async fn get_coin_from_storage(input: &Input, client: &HttpClient) -> anyhow::Result<Value> {
    let utxo = rpc::fetch_storage(input, client).await?;
    let coin_in_storage: Value = utxo.value;

    Ok(coin_in_storage)
}
