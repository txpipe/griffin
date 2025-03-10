Griffin Wallet
==============

This CLI wallet is based on a minimized version of the [Tuxedo wallet](https://github.com/Off-Narrative-Labs/Tuxedo/tree/main/wallet). It is provided for demonstration purposes of the UTxO features of the Griffin Solochain Node.

## Installation

You should have a properly installed Griffin node to build the wallet. After following the [instructions to do that](https://github.com/txpipe/griffin/blob/main/README.md#installation), run

```bash
cargo build --release -p griffin-wallet
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

## E-UTxO related commands

### Paying to a Script Address

This command pays some coins and assets to the script specified by `script-hex-file`. The optional parameters `script_params_cbor_file` and `datum-cbor-file` are used to pass the files containing the cbor of the parameter list expected by a parameterized script (if any) and the cbor of the inline datum to be included in the script output, if any. We also specify an input to be consumed by this transaction, and with `witness` the public key of an input owner (Shawn's pk implied by default). We can set as many inputs, witnesses and combinations of (policy, name, token-amount) as needed. The whole command looks like this:

```bash
./target/release/griffin-wallet pay-to-script \
--script-hex-file [PATH_TO_SCRIPT_HEX] \
--script_params_cbor_file [PATH_TO_PARAM_LIST_CBOR] \
--datum-cbor-file [PATH_TO_DATUM_CBOR] \
--input [INPUT_REF] \
--witness [WITNESSES] \
--amount [AMOUNT] \
--policy [POLICY_ID] \
--name [ASSET_NAME] \
--token-amount [TOKEN_AMOUNT]
```

For example, we can pay 2000 coins to the plutusV2 script version of [aiken's "hello-world" example](https://aiken-lang.org/example--hello-world/basics), spending an input that belongs to Shawn (its ref may vary) and with an inline datum that contains Shawn's pub key hash, like so:

```bash
./target/release/griffin-wallet pay-to-script \
--script-hex-file ./wallet/src/eutxo_examples/hello_world/script.txt \
--datum-cbor-file ./wallet/src/eutxo_examples/hello_world/datum.txt \
--input 25667b8e0fbf599ee2d640a4ab74accdb07a4c4b99b3a62f27e8e865f7ef577400000000 \
--amount 2000
```

### Spending a Script UTxO

In order to spend a script UTxO, we need to specify the file containing the script hex, the file of the parameter list cbor to be applied (if any), the file containing the redeemer cbor, the script input to be consumed and optionally the required signer(s) and witness(es) (if omitted, Shawn's values go as default). The complete command looks like this:

```bash
./target/release/griffin-wallet pay-to-script \
--script-hex-file [PATH_TO_SCRIPT_HEX] \
--script_params_cbor_file [PATH_TO_PARAM_LIST_CBOR] \
--redeemer-cbor-file [PATH_TO_REDEEMER_CBOR]
--input [INPUT_REF] \
--required-signer [REQUIRED_SIGNER]
--witness [WITNESSES]
```

For instance, to spend the UTxO sitting at the "hello-world" address that we created in [Paying to a Script Address](#paying-to-a-script-address), we use the following command (the input script ref may vary):

```bash
./target/release/griffin-wallet spend-script \
--script-hex-file ./wallet/src/eutxo_examples/hello_world/script.txt \
--redeemer-cbor-file ./wallet/src/eutxo_examples/hello_world/redeemer.txt \
--input 76196d9dc867051484c523112f2c4861795566edd5817e41db15be0c4d556e8500000000
```

### Minting an Asset

To mint an asset with some policy id, we need to specify the minting script hex, the parameter list to be applied (if any), the redeemer, an input to be consumed (every tx needs at least one, and we also need to pay for the min amount of coins in the output containing the newly minted asset), the witness(es) and recipient (by default, Shawn's pk and address are implied), the name of the asset to mint and its amount:

```bash
./target/release/griffin-wallet mint-asset \
--script-hex-file [PATH_TO_MINTING_POLICY_HEX] \
--script-params-cbor-file [PATH_TO_PARAM_LIST_CBOR] \
--redeemer-cbor-file [PATH_TO_REDEEMER_CBOR] \
--input [INPUT_REF] \
--witness [RECIPIENT] \
--recipient [RECIPIENT_ADDRESS] \
--name [ASSET_NAME] \
--token-amount [MINT_AMOUNT]
```

As an example, we can mint a singleton with name "oneShot", for a plutusV2 script version of the "one-shot" minting policy (takes a ref input as a parameter, and if minting checks that `input_is_consumed && minted_amount == 1`, or just `minted_amount == -1` if burning). In this case we are sending the minted amount back to Shawn (input ref may vary):

```bash
./target/release/griffin-wallet mint-asset \
--script-hex-file ./wallet/src/eutxo_examples/one_shot_mp/script.txt \
--script-params-cbor-file ./wallet/src/eutxo_examples/one_shot_mp/parameters.txt \
--redeemer-cbor-file ./wallet/src/eutxo_examples/one_shot_mp/redeemer.txt \
--input 25667b8e0fbf599ee2d640a4ab74accdb07a4c4b99b3a62f27e8e865f7ef577400000000 \
--name oneShot \
--token-amount 1
```
