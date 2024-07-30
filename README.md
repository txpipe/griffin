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
