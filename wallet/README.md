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
[2024-10-22T20:29:28Z INFO  utxo_wallet::sync] Initializing fresh sync from genesis 0x71e3eafccc87760b45bd08fd4bbdd4317346440166575e0b2b659fd289f05f45
[2024-10-22T20:29:28Z INFO  utxo_wallet] Number of blocks in the db: 0
[2024-10-22T20:29:28Z INFO  utxo_wallet] Wallet database synchronized with node to height 11
###### Unspent outputs ###########
701616402ad8899e0fa03de3aa496ea432bbd923eddcf5d588af16fd0cbc230c00000000: owner address 6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4, amount Coin(314), datum Some(CuteOutput).
```
This “genesis” UTxO belongs to Shawn's address. In order to spend it, we need to add his public/secret key pair (pk/sk) to the wallet keystore. We do this by generating the pair with the corresponding seed phrase:

```bash
$ ./target/release/utxo-wallet insert-key "news slush supreme milk chapter athlete soap sausage put clutch what kitten"

[2024-10-22T20:29:34Z INFO  utxo_wallet] Number of blocks in the db: 11
[2024-10-22T20:29:34Z INFO  utxo_wallet] Wallet database synchronized with node to height 13
The generated public key is 7b155093789404780735f4501c576e9f6e2b0a486cdec70e03e1ef8b9ef99274 (5Er65XH4...)
Associated address is 0x6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4
```

We use the `generate-key` command to have another pk/sk and address available for experimenting.

```
$ ./target/release/utxo-wallet generate-key

[2024-10-22T20:30:46Z INFO  utxo_wallet] Number of blocks in the db: 34
[2024-10-22T20:30:46Z INFO  utxo_wallet] Wallet database synchronized with node to height 37
Generated public key is aa2d29beac05bc17cd9e866848d85ae285b5041209d3e4fc81544f8f6e402d67 (5FuqQxFe...)
Generated Phrase is "grain feel nothing sail illness glue fashion soap brief chase cat march"
Associated address is 0x619d65450a97939f93bca4d2f691587ee080276d210e80b8312c727a66
```

Now we spend the output, generating two new UTxOs for the last address:

```
$ ./target/release/utxo-wallet spend-coins --input 701616402ad8899e0fa03de3aa496ea432bbd923eddcf5d588af16fd0cbc230c00000000 --amount 50 --amount 264 --recipient 0x619d65450a97939f93bca4d2f691587ee080276d210e80b8312c727a66 
[2024-10-22T20:31:46Z INFO  utxo_wallet] Number of blocks in the db: 45
[2024-10-22T20:31:46Z INFO  utxo_wallet] Wallet database synchronized with node to height 57
[2024-10-22T20:31:46Z INFO  utxo_wallet::money] Node's response to spend transaction: Ok("0xb9a07073ea5a5c6c9fa6c9d987424f9725dc219e5d5e57e6f4d4f31e5d6f3579")
Transaction queued. When accepted, the following UTxOs will become available:
"53dcda420d866f644026e35c75040f202e3e081d61b34e47b45a2fbf8768049900000000" worth Coin(50).
"53dcda420d866f644026e35c75040f202e3e081d61b34e47b45a2fbf8768049901000000" worth Coin(264).
```

All command-line arguments admit short versions (run `./target/release/utxo-wallet -h` for details). The next invocation splits the first UTxO and send the resulting ones back to Shawn: 

```bash
$ ./target/release/utxo-wallet spend-coins --input 53dcda420d866f644026e35c75040f202e3e081d61b34e47b45a2fbf8768049900000000 --amount 20 --amount 30 --witness aa2d29beac05bc17cd9e866848d85ae285b5041209d3e4fc81544f8f6e402d67

[2024-10-22T20:32:42Z INFO  utxo_wallet] Number of blocks in the db: 59
[2024-10-22T20:32:42Z INFO  utxo_wallet] Wallet database synchronized with node to height 76
[2024-10-22T20:32:42Z INFO  utxo_wallet::money] Node's response to spend transaction: Ok("0x3296de7b720ab7d77384758ca666e19dadc9690b84a20a313c3f1914480f41ee")
Transaction queued. When accepted, the following UTxOs will become available:
"898857a441840938cdf58c68b5e4d9ac3e894f4d89c157d6111cb05c26ea84a100000000" worth Coin(20). 
"898857a441840938cdf58c68b5e4d9ac3e894f4d89c157d6111cb05c26ea84a101000000" worth Coin(30). 
```

In this second example, we had to explicitly state the pk of the owning address to allow spenditure; in order to be successful, the sk must be stored in the wallet's keystore. (If the `--witness` argument is missing, Shawns pk is implied, cf. the first spend.)

The UTxO set at this point is

```bash
$ ./target/release/utxo-wallet show-all-outputs

[2024-10-22T20:32:54Z INFO  utxo_wallet] Number of blocks in the db: 76
[2024-10-22T20:32:54Z INFO  utxo_wallet] Wallet database synchronized with node to height 80
###### Unspent outputs ###########
53dcda420d866f644026e35c75040f202e3e081d61b34e47b45a2fbf8768049901000000: owner address 619d65450a97939f93bca4d2f691587ee080276d210e80b8312c727a66, amount Coin(264), datum None.
898857a441840938cdf58c68b5e4d9ac3e894f4d89c157d6111cb05c26ea84a100000000: owner address 6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4, amount Coin(20), datum None.
898857a441840938cdf58c68b5e4d9ac3e894f4d89c157d6111cb05c26ea84a101000000: owner address 6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4, amount Coin(30), datum None.
```

The *balance* summarizes coins for each address:

```bash
$ ./target/release/utxo-wallet show-balance

[2024-10-22T20:33:29Z INFO  utxo_wallet] Number of blocks in the db: 80
[2024-10-22T20:33:29Z INFO  utxo_wallet] Wallet database synchronized with node to height 91
Balance Summary
6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4: 50
619d65450a97939f93bca4d2f691587ee080276d210e80b8312c727a66: 264
--------------------
total      : 314
```
