Griffin Wallet
==============

This CLI wallet is based on a minimized version of the [Tuxedo wallet](https://github.com/Off-Narrative-Labs/Tuxedo/tree/main/wallet). It is provided for demonstration purposes of the UTxO features of the Griffin Solochain Node.

## Installation

You should have a properly installed Griffin node to build the wallet. After following the [instructions to do that](https://github.com/txpipe/griffin/blob/main/README.md#installation), run

```bash
cargo +1.86 build --release -p griffin-wallet
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
./target/release/griffin-wallet show-all-outputs
```

When this is done for the first, the output will look like this:

```
[2024-11-14T12:37:20Z INFO  griffin_wallet] Number of blocks in the db: 5
[2024-11-14T12:37:20Z INFO  griffin_wallet] Wallet database synchronized with node to height 6
###### Unspent outputs ###########
998f074b5357d465fdd99198c65af6a418522e5a1688e2674c935702fef38d0600000000: owner address 6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4, datum Some(CuteOutput), amount: 314000000 Coins, Multiassets:
  (0x0298…2005) tokenA: 271000000
  (0x0298…2005) tokenB: 1123581321
```
This “genesis” UTxO belongs to Shawn's address. In order to spend it, we need to add his public/secret key pair (pk/sk) to the wallet keystore. We do this by generating the pair with the corresponding seed phrase:

```
$ ./target/release/griffin-wallet insert-key "news slush supreme milk chapter athlete soap sausage put clutch what kitten"

[2024-11-14T12:38:19Z INFO  griffin_wallet] Number of blocks in the db: 6
[2024-11-14T12:38:19Z INFO  griffin_wallet] Wallet database synchronized with node to height 26
The generated public key is 7b155093789404780735f4501c576e9f6e2b0a486cdec70e03e1ef8b9ef99274 (5Er65XH4...)
Associated address is 0x6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4
```

We use the `generate-key` command to have another pk/sk and address available for experimenting.

```
$ ./target/release/griffin-wallet generate-key

[2024-11-14T12:38:53Z INFO  griffin_wallet] Number of blocks in the db: 26
[2024-11-14T12:38:53Z INFO  griffin_wallet] Wallet database synchronized with node to height 37
Generated public key is 3538f889235842527b946255962241591cdc86cb99ba566afde335ae94262ee4 (5DGVKT7k...)
Generated Phrase is "vibrant assume service vibrant six unusual trumpet ten truck raise verify soft"
Associated address is 0x614fdf13c0aabb2c2e6df7a0ac0f5cb5aaabca448af8287e54681273dd
```

Now we spend the output, generating a new UTxO for the last address:

```
$ ./target/release/griffin-wallet spend-value --input 998f074b5357d465fdd99198c65af6a418522e5a1688e2674c935702fef38d0600000000 --amount 200000000 --recipient 0x614fdf13c0aabb2c2e6df7a0ac0f5cb5aaabca448af8287e54681273dd

[2024-11-14T12:41:18Z INFO  griffin_wallet] Number of blocks in the db: 37
[2024-11-14T12:41:18Z INFO  griffin_wallet] Wallet database synchronized with node to height 86
Note: Excess input amount goes to Shawn.
[2024-11-14T12:41:18Z INFO  griffin_wallet::money] Node's response to spend transaction: Ok("0x5a1974d3e3d32c075b220513125c9457ac9efc59a651d36704c0c7a4e389b6e6")
Transaction queued. When accepted, the following UTxOs will become available:
"dcb998d9e000c19fd20e41afeff6e1e0d9366e6e6c756c8173e52fc8061638f600000000" worth Coin(200000000).
"dcb998d9e000c19fd20e41afeff6e1e0d9366e6e6c756c8173e52fc8061638f601000000" worth Multiasset(114000000, EncapBTree({0x0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005: EncapBTree({AssetName("tokenA"): 271000000, AssetName("tokenB"): 1123581321})})).
```

All command-line arguments admit short versions (run `./target/release/griffin-wallet -h` for details). The next invocation spends the first UTxO and sends some coins back to Shawn:

```
$ ./target/release/griffin-wallet spend-value --input dcb998d9e000c19fd20e41afeff6e1e0d9366e6e6c756c8173e52fc8061638f600000000 --amount 150000000 --witness 3538f889235842527b946255962241591cdc86cb99ba566afde335ae94262ee4

[2024-11-14T12:47:45Z INFO  griffin_wallet] Number of blocks in the db: 184
[2024-11-14T12:47:45Z INFO  griffin_wallet] Wallet database synchronized with node to height 215
Note: Excess input amount goes to Shawn.
[2024-11-14T12:47:45Z INFO  griffin_wallet::money] Node's response to spend transaction: Ok("0xbcc0e3f157c660e022890ea9a8ddf1e7a324dd7ae30496a774d4f04046b5097a")
Transaction queued. When accepted, the following UTxOs will become available:
"bf73bc5bcf3afa75a7070041c635d78f6613aa3b753956e93053077cf9dc4b8e00000000" worth Coin(150000000).
"bf73bc5bcf3afa75a7070041c635d78f6613aa3b753956e93053077cf9dc4b8e01000000" worth Coin(50000000).
```

In this second example, we had to explicitly state the pk of the owning address to allow spenditure; in order to be successful, the sk must be stored in the wallet's keystore. (If the `--witness` argument is missing, Shawns pk is implied, cf. the first spend.)

The UTxO set at this point is

```
$ ./target/release/griffin-wallet show-all-outputs

[2024-11-14T12:48:44Z INFO  griffin_wallet] Number of blocks in the db: 215
[2024-11-14T12:48:44Z INFO  griffin_wallet] Wallet database synchronized with node to height 234
###### Unspent outputs ###########
bf73bc5bcf3afa75a7070041c635d78f6613aa3b753956e93053077cf9dc4b8e00000000: owner address 6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4, datum None, amount: 150000000 Coins
bf73bc5bcf3afa75a7070041c635d78f6613aa3b753956e93053077cf9dc4b8e01000000: owner address 6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4, datum None, amount: 50000000 Coins
dcb998d9e000c19fd20e41afeff6e1e0d9366e6e6c756c8173e52fc8061638f601000000: owner address 6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4, datum None, amount: 114000000 Coins, Multiassets:
  (0x0298…2005) tokenA: 271000000
  (0x0298…2005) tokenB: 1123581321

```

Finally, to send some coins *and* `tokenA`s from the last UTxO to the other account, we do:
```
$ ./target/release/griffin-wallet spend-value --input dcb998d9e000c19fd20e41afeff6e1e0d9366e6e6c756c8173e52fc8061638f601000000 --amount 14000000 --policy 0x0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005 --name tokenA --token-amount 200000000 --recipient 0x614fdf13c0aabb2c2e6df7a0ac0f5cb5aaabca448af8287e54681273dd

[2024-11-14T12:54:28Z INFO  griffin_wallet] Number of blocks in the db: 250
[2024-11-14T12:54:28Z INFO  griffin_wallet] Wallet database synchronized with node to height 349
Note: Excess input amount goes to Shawn.
[2024-11-14T12:54:28Z INFO  griffin_wallet::money] Node's response to spend transaction: Ok("0xa7ad4765e2ab4767e434fc6c117929a8871288c094a428164071c63bd9f0490a")
Transaction queued. When accepted, the following UTxOs will become available:
"ae2bcf3d0b2ace1f957176f17bac72e3fc2e518c82b41a9bdd622bb82318e4b200000000" worth Multiasset(14000000, EncapBTree({0x0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005: EncapBTree({AssetName("tokenA"): 200000000})})).
"ae2bcf3d0b2ace1f957176f17bac72e3fc2e518c82b41a9bdd622bb82318e4b201000000" worth Multiasset(100000000, EncapBTree({0x0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005: EncapBTree({AssetName("tokenA"): 71000000, AssetName("tokenB"): 1123581321})})).
```

The *balance* summarizes `Value` amounts for each address:

```
$ ./target/release/griffin-wallet show-balance

[2024-11-14T12:54:34Z INFO  griffin_wallet] Number of blocks in the db: 349
[2024-11-14T12:54:34Z INFO  griffin_wallet] Wallet database synchronized with node to height 351
Balance Summary
6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4: 300000000 Coins, Multiassets:
  (0x0298…2005) tokenA: 71000000
  (0x0298…2005) tokenB: 1123581321
614fdf13c0aabb2c2e6df7a0ac0f5cb5aaabca448af8287e54681273dd: 14000000 Coins, Multiassets:
  (0x0298…2005) tokenA: 200000000
--------------------
total      : 314000000 Coins, Multiassets:
  (0x0298…2005) tokenA: 271000000
  (0x0298…2005) tokenB: 1123581321
```


## Complete Transaction Builder

In order to reproduce more complex wallet commands, like consuming a script input or minting an asset, we provide a more complete transaction builder via the `build-tx` command. The whole command has the following shape:

```bash
./target/release/griffin-wallet build-tx \
--inputs-info PATH_TO_INPUTS_INFO_JSON \
--outputs-info PATH_TO_OUTPUTS_INFO_JSON \
--scripts-info PATH_TO_SCRIPTS_INFO_JSON \
--mintings-info PATH_TO_MINTINGS_INFO_JSON \
--witness [PUB_KEY] \
--required-signer [PUB_KEY_HASH] \
--validity-interval-start START_OF_VALIDITY_INTERVAL \
--ttl TIME_TO_LIVE
```

The optional parameters are: `scripts-info`, `mintings-info`, `witness` (can be specified multiple times and defaults to Shawn's public key), `required-signer` (analogous to `witness`), `validity-interval-start` and `ttl` (the last two default to `None`).

There are example contracts and json files for testing this command in the `eutxo_examples` directory.
