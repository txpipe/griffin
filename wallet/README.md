Demo UTxO Wallet
================

This is a minimized version of the [Tuxedo wallet](https://github.com/Off-Narrative-Labs/Tuxedo/tree/main/wallet) for demonstration purposes of the UTxO features of the Griffin Solochain Node.

## Installation

You should have a properly installed Griffin node to build the wallet. After following the [instructions to do that](https://github.com/txpipe/griffin/blob/main/README.md#installation), run

```bash
cargo +nightly build --release -p utxo-wallet
```

As explained in the node installation instructions, omitting the `--release` will build the "debug" version.

## Basic usage

In terminal, run the node in development mode:

```bash
./target/release/griffin-solochain-node --dev
```

In another terminal, one can interact with the node by issuing wallet commands. Every time the wallet starts (without the `--help` or `--version` command-line options), it will try to synchronize its database with the present chain state, unless there is a mismatch with the genesis hash.

To list the whole UTxO set, run

```bash
./target/release/utxo-wallet show-all-outputs
```

When this is done for the first, the output will look like this:

```bash
[2024-09-19T21:27:40Z INFO  utxo_wallet] Number of blocks in the db: 0
[2024-09-19T21:27:41Z INFO  utxo_wallet] Wallet database synchronized with node to height 26
###### Unspent outputs ###########
149b3e2702eef1055ee08362b22638305fcb751f4fde6bbef763af89f9c84c7900000000: owner 0xd2bf4b844dfefd6772a8843e669f943408966a977e3ae2af1dd78e0f55f4df67, amount 314
```

The following splits that UTxO in three parts (assigned to Shawn by default). The remaining 14 coins are lost.

```bash
$ ./target/release/utxo-wallet spend-coins --input 149b3e2702eef1055ee08362b22638305fcb751f4fde6bbef763af89f9c84c7900000000 --amount 100 --amount 150 --amount 50

[2024-09-19T21:28:08Z INFO  utxo_wallet] Number of blocks in the db: 26
[2024-09-19T21:28:08Z INFO  utxo_wallet] Wallet database synchronized with node to height 35
[2024-09-19T21:28:08Z INFO  utxo_wallet::money] Node's response to spend transaction: Ok("0x0de44857fb6301e0e9f316c54de527f6fee1893a533c4273ea0f1497581d039c")
Created "16a0afadf19d6b7e62784a1441271d1f731260623be423c33187a96e3cc8d29700000000" worth 100. 
Created "16a0afadf19d6b7e62784a1441271d1f731260623be423c33187a96e3cc8d29701000000" worth 150. 
Created "16a0afadf19d6b7e62784a1441271d1f731260623be423c33187a96e3cc8d29702000000" worth 50. 
```

All command-line arguments admit short versions (run `./target/release/utxo-wallet -h` for details). The next one sends 60 coins from the second output to some arbitrary key:

```bash
$ ./target/release/utxo-wallet spend-coins --input 16a0afadf19d6b7e62784a1441271d1f731260623be423c33187a96e3cc8d29701000000 --amount 60 --recipient 0x524414d5af095bcb4cadc0cf9f8bfbeeeaa8cc34f2df41c3bc4ed953cf8a4367

[2024-09-19T21:28:55Z INFO  utxo_wallet] Number of blocks in the db: 35
[2024-09-19T21:28:55Z INFO  utxo_wallet] Wallet database synchronized with node to height 51
[2024-09-19T21:28:55Z INFO  utxo_wallet::money] Node's response to spend transaction: Ok("0x2e71606dc18aeb4ba948b1e0cd6cb5b85bbb29589b83e68169d416e1ac17dbc6")
Created "d054364bdba58df9fae05e2388e09b607ed7767e91cc7d3af9bf4776f1a87b9f00000000" worth 60. 
```

The UTxO set at this point is

```bash
$ ./target/release/utxo-wallet show-all-outputs

[2024-09-19T21:29:14Z INFO  utxo_wallet] Number of blocks in the db: 51
[2024-09-19T21:29:14Z INFO  utxo_wallet] Wallet database synchronized with node to height 57
###### Unspent outputs ###########
16a0afadf19d6b7e62784a1441271d1f731260623be423c33187a96e3cc8d29700000000: owner 0xd2bf4b844dfefd6772a8843e669f943408966a977e3ae2af1dd78e0f55f4df67, amount 100
16a0afadf19d6b7e62784a1441271d1f731260623be423c33187a96e3cc8d29702000000: owner 0xd2bf4b844dfefd6772a8843e669f943408966a977e3ae2af1dd78e0f55f4df67, amount 50
d054364bdba58df9fae05e2388e09b607ed7767e91cc7d3af9bf4776f1a87b9f00000000: owner 0x524414d5af095bcb4cadc0cf9f8bfbeeeaa8cc34f2df41c3bc4ed953cf8a4367, amount 60
```

The *balance* summarizes coins for each address:

```bash
$ ./target/release/utxo-wallet show-balance

[2024-09-19T21:29:34Z INFO  utxo_wallet] Number of blocks in the db: 57
[2024-09-19T21:29:34Z INFO  utxo_wallet] Wallet database synchronized with node to height 64
Balance Summary
0x5244…4367: 60
0xd2bf…df67: 150
--------------------
total      : 210
```

At this development stage, coin minting is allowed. As with every other transaction, an input is required, whose coins are channeled back as a new UTxO.

```bash
$ ./target/release/utxo-wallet mint-coins --amount 1000 --recipient 524414d5af095bcb4cadc0cf9f8bfbeeeaa8cc34f2df41c3bc4ed953cf8a4367 --input 16a0afadf19d6b7e62784a1441271d1f731260623be423c33187a96e3cc8d29700000000

[2024-09-19T21:43:59Z INFO  utxo_wallet] Number of blocks in the db: 64
[2024-09-19T21:43:59Z INFO  utxo_wallet] Wallet database synchronized with node to height 352
[2024-09-19T21:43:59Z INFO  utxo_wallet::money] Node's response to mint-coin transaction: Ok("0x8e2f5536cefe8f5443b59da404fdc7997f2f922b777812a3de63092d98cab3c6")
Minted "290428f8a6b202aaba22c6db9693394fa02a03c130846f3d23f8eca1f262506200000000" worth 1000. 

$ ./target/release/utxo-wallet show-balance

[2024-09-19T21:45:14Z INFO  utxo_wallet] Number of blocks in the db: 352
[2024-09-19T21:45:14Z INFO  utxo_wallet] Wallet database synchronized with node to height 377
Balance Summary
0xd2bf…df67: 150
0x5244…4367: 1060
--------------------
total      : 1210
```
