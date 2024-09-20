# Griffin

We argue that there are scenarios, like semi-permissioned networks, where transaction throughput and block finality is favored over protection to adversarial conditions.

The Substrate framework allows developers to build use-case specific blockchain networks. Different consensus and ledger components can be integrated to build a system that follows a specific tradeoff strategy.

The Cardano developer community has made huge strides in terms of best-practices and patterns that leverage the eUTxO model and the Plutus VM in particular.

We want to provide the tools for Cardano developers to leverage their Plutus experience when building

We'll build a Substrate-compatible runtime with the following special capabilities:

- UTxO-based ledger: this ledger will resemble as much as possible the Cardano ledger, with the exception of any stacking, delegation or governance primitives.
- Extended UTxO primitives: we'll replicate the programability primitives around UTxO (datums, redeemers, scripts, etc) so that these concepts remains analogous to Cardano.
- Plutus VM: we'll integrate a virtual machine capable of executing Plutus scripts that can be created using existing Plutus tooling and languages, such as Aiken.

We'll also build a client node reference implementation using Substrate that integrates the following components:

- RPC interface: a mechanism to interact with the node using a network RPC interface, used for extrinsic event submission and management operations.
- Aura consensus: a proof-of-authority (PoA) consensus protocol where only approved nodes are allowed to create new blocks.
- Grandpa block finality: a Byzantine fault tolerant finality gadget that provides deterministic finality.
- Libp2p networking: a battle-tested peer-to-peer networking library providing transport, discovery and routing mechanism.


## Installation

Depending on your operating system and Rust version, there might be additional packages required to compile the node and the wallet. Check the [install](https://docs.substrate.io/install/) instructions for your platform for the most common dependencies.

### Building

Use the following command to build the node:

```bash
cargo build --package griffin-solochain-node --release
```

### Debug Build

For a faster building process (but resulting in unoptimized binaries), you can build both the node and the wallet in debug mode by running the previous commands without the `--release` flag. In this case, the resulting binaries will be located in the `./target/debug` directory.

## Running

The following command starts a block-producing development node that doesn't persist state:

```bash
./target/release/griffin-solochain-node --dev
```

To purge the development chain's state, run the following:

```bash
./target/release/griffin-solochain-node purge-chain --dev
```

Development chains are set to 

- maintain state in a temporary folder while the node is running;
- use the Alice account as default validator authority; and
- are preconfigured with a genesis state (/node/src/chain_spec.rs).


To preserve the chain state between runs, specify a base path by running a command similar to the following:

```bash
// Create a folder to use as the db base path
$ mkdir my-chain-state

// Use of that folder to store the chain state
$ ./target/release/solochain-template-node --dev --base-path ./my-chain-state/

// Check the folder structure created inside the base path after running the chain
$ ls ./my-chain-state
chains
$ ls ./my-chain-state/chains/
dev
$ ls ./my-chain-state/chains/dev
db keystore network
```

## Testing

Development node features can be tested by using the [demo UTxO wallet](https://github.com/txpipe/griffin/tree/main/wallet#demo-utxo-wallet).
