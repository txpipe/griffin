use aiken/list
use aiken/transaction.{Datum, InlineDatum, Input, Output, Redeemer, Transaction}
use aiken/transaction/credential.{ScriptCredential, VerificationKeyCredential}
use aiken/transaction/value.{AssetName, PolicyId, Value}
use types.{OrderDatum, OrderRedeemer, PubKeyHash}

// This module provides a set of utility functions used across the order contract.

/// Checks whether for each currency-symbol and token-name pair in `x`,
/// the associated quantity is less than or equal to the corresponding quantity in `y`.
/// If `y` does not have a corresponding pair, it's treated as having a quantity of `0`.
pub fn leq(x: Value, y: Value) -> Bool {
  let flattened_x = value.flatten(x)

  list.all(
    flattened_x,
    fn(val) {
      let (policy_x, asset_x, quantity_x) = val

      value.quantity_of(y, policy_x, asset_x) <= quantity_x
    },
  )
}

/// Returns the Order UTxO present in the inputs of a transaction.
pub fn get_order_utxo(tx: Transaction) -> Input {
  expect [utxo] = tx.inputs|> list.filter(is_script_utxo)
  utxo
}

/// Returns the value in the Order UTxO (disregarding the control token).
pub fn get_order_value(
  transaction: Transaction,
  control_policy_id,
  control_asset_name,
) -> Value {
  transaction
    |> get_order_utxo()
    |> fn(input: Input) { input.output.value }
    |> value.add(control_policy_id, control_asset_name, -1)
}

/// Verifies if an input UTxO belongs to a script.
pub fn is_script_utxo(input: Input) -> Bool {
  when input.output.address.payment_credential is {
    VerificationKeyCredential(_) -> False
    ScriptCredential(_) -> True
  }
}

/// Returns the minting information of a transaction.
pub fn get_minting_info(tx: Transaction) -> (PolicyId, AssetName, Int) {
  expect [info] = tx.mint |> value.from_minted_value |> value.flatten
  info
}

/// Returns the first output of the transaction in the script context.
pub fn get_first_output(tx: Transaction) -> Output {
  expect Some(stake_utxo) = tx.outputs |> list.head
  stake_utxo
}

/// Returns the total value paid to a wallet by a pending transaction.
pub fn value_paid_to(
  payment_key: PubKeyHash,
  staking_key: Option<PubKeyHash>,
  tx: Transaction
) -> Value {
  let address =
    when staking_key is {
      None -> credential.from_verification_key(payment_key)
      Some(stake_k) ->
        credential.from_verification_key(payment_key)
          |> credential.with_delegation_key(stake_k)
    }

  let utxos_at_addr =
    list.filter(tx.outputs, fn(utxo) { utxo.address == address })
  let values = list.map(utxos_at_addr, fn(utxo) { utxo.value })

  list.reduce(values, value.zero(), value.merge)
}

/// Converts an arbitrary Data type into a custom Datum (OrderDatum).
pub fn to_order_datum(data: Data) -> OrderDatum {
  expect InlineDatum(datum): Datum = data
  expect datum: OrderDatum = datum
  datum
}

/// Converts a Datum into an arbitrary Data type.
pub fn datum_to_data(datum: Datum) -> Data {
  let data: Data = datum
  data
}

// Converts a Redeemer into a custom Redeemer (OrderRedeemer).
pub fn to_order_redeemer(redeemer: Redeemer) -> OrderRedeemer {
  expect order_redeemer: OrderRedeemer = redeemer
  order_redeemer
}

// Converts a custom Redeemer (OrderRedeemer) into a Redeemer.
pub fn redeemer_to_data(order_redeemer: OrderRedeemer) -> Redeemer {
  let redeemer: Redeemer = order_redeemer
  redeemer
}
