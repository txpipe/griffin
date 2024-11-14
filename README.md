# Griffin

We argue that there are scenarios, like semi-permissioned networks, where transaction throughput and block finality is favored over protection to adversarial conditions.

The Substrate framework allows developers to build use-case specific blockchain networks. Different consensus and ledger components can be integrated to build a system that follows a specific tradeoff strategy.

The Cardano developer community has made huge strides in terms of best-practices and patterns that leverage the eUTxO model and the Plutus VM in particular.

We want to provide the tools for Cardano developers to leverage their Plutus experience when building

We'll build a Substrate-compatible runtime with the following special capabilities:

- UTxO-based ledger: this ledger will resemble as much as possible the Cardano ledger, with the exception of any staking, delegation or governance primitives.
- Extended UTxO primitives: we'll replicate the programability primitives around UTxO (datums, redeemers, scripts, etc) so that these concepts remains analogous to Cardano.
- Plutus VM: we'll integrate a virtual machine capable of executing Plutus scripts that can be created using existing Plutus tooling and languages, such as Aiken.

We'll also build a client node reference implementation using Substrate that integrates the following components:

- RPC interface: a mechanism to interact with the node using a network RPC interface, used for extrinsic event submission and management operations.
- Aura consensus: a proof-of-authority (PoA) consensus protocol where only approved nodes are allowed to create new blocks.
- Grandpa block finality: a Byzantine fault tolerant finality gadget that provides deterministic finality.
- Libp2p networking: a battle-tested peer-to-peer networking library providing transport, discovery and routing mechanism.


## Installation

Depending on your operating system and Rust version, there might be additional packages required to compile the node and the wallet. Check the [install](https://docs.substrate.io/install/) instructions for your platform for the most common dependencies.

In particular, you will need the `nightly` Rust toolchain, add to it the `wasm32-unknown-unknown` target, and the `rust-src` component.

### Building

Use the following command to build the node:

```bash
cargo +nightly build --package griffin-solochain-node --release
```

*Note on exhaustion*. The building process is **memory-intensive**, and you might need to close some programs (browser, etc.) if you are getting errors during the last part (e.g. from `collect2` or `ld` at the linking step).

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

### Wallet

Development node features can be tested by using the [demo wallet](https://github.com/txpipe/griffin/tree/main/wallet#demo-utxo-wallet).

### Two-node interaction

The preset genesis allows to run a block-authoring node and a listening node very easily.

1. In a terminal at the root of the repository, run the authoring node using

  ```bash
  ./target/release/griffin-solochain-node --chain local --port 30333 --rpc-port 9945 --rpc-methods Unsafe --alice
  ```
2. At the start, the node will signal its identity,

  ```
  2024-11-14 16:02:00 🏷  Local node identity is: 12D3KooWKzwi7xW6d7dKNwDU6YGXCgC52BLd1VDyjvHWrqcG1uz3
  ```
3. In a new terminal, run the listening node:

  ```
  ./target/release/griffin-solochain-node --base-path /tmp/node01 --chain local --port 30333 --rpc-port 9944 --validator --rpc-methods Unsafe --name hola --node-key 0000000000000000000000000000000000000000000000000000000000000002 --bootnodes /ip4/127.0.0.1/tcp/30333/p2p/<AUTHORING_NODE_IDENTITY>
  ```
  
  where `<AUTHORING_NODE_IDENTITY>` should be replaced by the appropriate id.
4. The wallet will talk to the node having `--rpc-port` equal to 9944.

It might be necessary to delete the nodes' DBs (through the `purge-chain` command or manually, e.g., by erasing the `/tmp/node01` folder for the listening node) if this is not first the node is run *locally*.

### Custom genesis

The `--chain` flag can be used to set a custom genesis through a JSON. An sample file is located [here](https://github.com/txpipe/griffin/blob/main/examples/genesis.json), and the example above also works when replacing `--chain local` by `--chain examples/genesis.json`.
