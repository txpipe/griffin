//! Test Wallet's Command Line Interface.

use std::path::PathBuf;

use clap::{ArgAction::Append, Args, Parser, Subcommand};
use griffin_core::types::{Coin, Input, Address};
use crate::{
    input_from_string,
    DEFAULT_ENDPOINT,
    address_from_string,
    h256_from_string,
    H256,
};
use runtime::genesis::{
    SHAWN_PUB_KEY,
    SHAWN_ADDRESS,
};

/// The default number of coins to be minted.
pub const DEFAULT_MINT_VALUE: &str = "100";

/// The wallet's main CLI struct
#[derive(Debug, Parser)]
#[command(about, version)]
pub struct Cli {
    #[arg(long, short, default_value_t = DEFAULT_ENDPOINT.to_string())]
    /// RPC endpoint of the node that this wallet will connect to.
    pub endpoint: String,

    #[arg(long, short('d'))]
    /// Path where the wallet data is stored. Default value is platform specific.
    pub base_path: Option<PathBuf>,

    #[arg(long, verbatim_doc_comment)]
    /// Skip the initial sync that the wallet typically performs with the node.
    /// The wallet will use the latest data it had previously synced.
    pub no_sync: bool,

    #[arg(long)]
    /// A temporary directory will be created to store the configuration and will be deleted at the end of the process.
    /// path will be ignored if this is set.
    pub tmp: bool,

    #[arg(long, verbatim_doc_comment)]
    /// Specify a development wallet instance, using a temporary directory (like --tmp).
    /// The keystore will contain the development key Shawn.
    pub dev: bool,

    #[arg(long, verbatim_doc_comment)]
    /// Erases the wallet DB before starting.
    pub purge_db: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// The tasks supported by the wallet
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Mint coins, optionally amount and publicKey of owner can be passed.
    /// If amount is not passed, 100 coins are minted.
    /// If publickKey of owner is not passed, then by default SHAWN_PUB_KEY is used.
    #[command(verbatim_doc_comment)]
    MintCoins(MintCoinArgs),

    /// Verify that a particular coin exists.
    /// Show its value and owner from both chain storage and the local database.
    #[command(verbatim_doc_comment)]
    VerifyCoin {
        /// A hex-encoded output reference
        #[arg(value_parser = input_from_string)]
        input: Input,
    },

    /// Spend some coins.
    #[command(verbatim_doc_comment)]
    SpendCoins(SpendArgs),

    /// Insert a private key into the keystore to later use when signing transactions.
    InsertKey {
        /// Seed phrase of the key to insert.
        seed: String,
    },

    /// Generate a private key using either some or no password and insert into the keystore.
    GenerateKey {
        /// Initialize a public/private key pair with a password
        password: Option<String>,
    },

    /// Show public information about all the keys in the keystore.
    ShowKeys,

    /// Remove a specific key from the keystore.
    /// WARNING! This will permanently delete the private key information.
    /// Make sure your keys are backed up somewhere safe.
    #[command(verbatim_doc_comment)]
    RemoveKey {
        /// The public key to remove
        #[arg(value_parser = h256_from_string)]
        pub_key: H256,
    },

    /// For each key tracked by the wallet, shows the sum of all UTXO values owned by that key.
    /// This sum is sometimes known as the "balance".
    #[command(verbatim_doc_comment)]
    ShowBalance,

    /// Show the complete list of UTXOs known to the wallet.
    ShowAllOutputs,
}

#[derive(Debug, Args)]
pub struct MintCoinArgs {
    /// An input to be consumed by this transaction.
    #[arg(long, short, verbatim_doc_comment, value_parser = input_from_string)]
    pub input: Input,

    /// Pass the amount to be minted.
    #[arg(long, short, verbatim_doc_comment, action = Append,default_value = DEFAULT_MINT_VALUE)]
    pub amount: Coin,

    /// 28-byte hash-address of the recipient.
    #[arg(long, short, verbatim_doc_comment, value_parser = address_from_string, default_value = SHAWN_ADDRESS)]
    pub recipient: Address,
}

#[derive(Debug, Args)]
pub struct SpendArgs {
    /// An input to be consumed by this transaction. This argument may be specified multiple times.
    #[arg(long, short, verbatim_doc_comment, value_parser = input_from_string, required = true)]
    pub input: Vec<Input>,

    /// 32-byte H256 public key of an input owner.
    /// Their pk/sk pair must be registered in the wallet's keystore.
    #[arg(long, short, verbatim_doc_comment, value_parser = h256_from_string, default_value = SHAWN_PUB_KEY)]
    pub witness: Vec<H256>,

    /// 29-byte hash-address of the recipient.
    #[arg(long, short, verbatim_doc_comment, value_parser = address_from_string, default_value = SHAWN_ADDRESS)]
    pub recipient: Address,

    /// An output amount (only supports `Coin`). For the transaction to be
    /// accepted by the node, the sum of the outputs must equal the sum of the inputs.
    #[arg(long, short, verbatim_doc_comment, action = Append)]
    pub amount: Vec<Coin>,
}
