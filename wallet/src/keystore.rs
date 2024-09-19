//! Wallet's local keystore.

use anyhow::anyhow;
use sc_keystore::LocalKeystore;
use sp_core::{
    crypto::{Pair as PairT, KeyTypeId},
    sr25519::Pair,
    H256,
};
use sp_keystore::Keystore;
use std::path::Path;
use runtime::genesis::SHAWN_PHRASE;

/// A KeyTypeId to use in the keystore for Griffin transactions.
const KEY_TYPE: KeyTypeId = KeyTypeId(*b"_gri");

/// Insert the example "Shawn" key into the keystore for the current session only.
pub fn insert_development_key_for_this_session(
    keystore: &LocalKeystore
) -> anyhow::Result<()> {
    keystore.sr25519_generate_new(KEY_TYPE, Some(SHAWN_PHRASE))?;

    Ok(())
}

/// Insert the private key associated with the given seed into the keystore for later use.
pub fn insert_key(keystore: &LocalKeystore, seed: &str) -> anyhow::Result<()> {
    // We need to provide a public key to the keystore manually, so let's calculate it.
    let public_key = Pair::from_phrase(seed, None)?.0.public();
    println!("The generated public key is {:?}", public_key);
    keystore
        .insert(KEY_TYPE, seed, public_key.as_ref())
        .map_err(|()| anyhow!("Error inserting key"))?;

    Ok(())
}

/// Generate a new key from system entropy and insert it into the keystore, optionally
/// protected by a password.
pub fn generate_key(
    keystore: &LocalKeystore,
    password: Option<String>
) -> anyhow::Result<()> {
    let (pair, phrase, _) = Pair::generate_with_phrase(password.as_deref());
    println!("Generated public key is {:?}", pair.public());
    println!("Generated Phrase is {}", phrase);
    keystore
        .insert(KEY_TYPE, phrase.as_ref(), pair.public().as_ref())
        .map_err(|()| anyhow!("Error inserting key"))?;

    Ok(())
}

pub fn get_keys(
    keystore: &LocalKeystore
) -> anyhow::Result<impl Iterator<Item = Vec<u8>>> {
    Ok(keystore.keys(KEY_TYPE)?.into_iter())
}

/// Removes key from keystore. Call with care.
pub fn remove_key(keystore_path: &Path, pub_key: &H256) -> anyhow::Result<()> {
    // The keystore doesn't provide an API for removing keys, so we
    // remove them from the filesystem directly
    let filename = format!("{}{}", hex::encode(KEY_TYPE.0), hex::encode(pub_key.0));
    let path = keystore_path.join(filename);

    std::fs::remove_file(path)?;

    Ok(())
}
