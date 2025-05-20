use aiken/list
use aiken/transaction.{Output, ScriptContext, Transaction}
use aiken/transaction/credential
use aiken/transaction/value
use types.{
  AssetClass, CancelOrder, DatumValue, OrderDatum, OrderInfo, OrderRedeemer,
  ResolveOrder,
}
use utils

// This module defines the validation logic for the order contract, encompassing both the primary
// validator function and the minting policy. It ensures the correctness of redeemers, inputs,
// and minting operations in accordance with the contract's specifications.

validator {
  /// `spend` function
  ///
  /// This function validates a specific order transaction based on the provided datum, redeemer,
  /// and context.
  ///
  /// # Parameters:
  /// - `datum`: Contains the information related to the order, including the sender's payment hash,
  ///            the token's asset class, and the token's amount.
  /// - `redeemer`: Indicates the action to be taken on the order, i.e., whether it's a cancellation
  ///               or a resolution of the order.
  /// - `context`: Provides the surrounding context of the transaction, enabling access to
  ///              transaction details.
  ///
  /// # Returns:
  /// - `true` if the order is valid, `false` otherwise.
  fn spend(
    datum: OrderDatum,
    redeemer: OrderRedeemer,
    context: ScriptContext,
  ) -> Bool {
    // Retrieves minting information from the transaction.
    let (minted_policy, minted_name, minted_quantity) =
      utils.get_minting_info(context.transaction)

    // Checks if the redeemer action (either cancel or resolve) is valid.
    let is_redeemer_valid =
      when redeemer is {
        CancelOrder -> {
          // Retrieves extra signatories of the transaction. Expecting a single signer address.
          expect [signer_addr] = context.transaction.extra_signatories
          // Checks if the signer is the original sender.
          (signer_addr == datum.info.sender_payment_hash)?
        }
        ResolveOrder -> {
          // Creates the sender's address based on the datum's sender information.
          // Constructs the sender's address with staking credentials if a staking hash is present.
          // Otherwise, it creates an address with only the payment credential.
          let sender_address =
            credential.from_verification_key(datum.info.sender_payment_hash)

          // Retrieves the payment made to the sender in the current transaction.
          let sender_payment_utxo = utils.get_first_output(context.transaction)

          // Checks if the address of the UTXO matches the expected sender address.
          let is_sender_payment_utxo_address_correct =
            sender_payment_utxo.address == sender_address

          // Extracts the asset policy, asset name, and amount from the flattened value of the UTXO,
          // assuming it contains only one asset type (the one intended for the sender).
          let (asset_policy, asset_name, amount) =
            if datum.info.token.asset_class.policy == value.ada_policy_id {
              expect [(asset_policy, asset_name, amount)] =
                value.flatten(sender_payment_utxo.value)
              (asset_policy, asset_name, amount)
            } else {
              expect [(asset_policy, asset_name, amount)] =
                value.without_lovelace(sender_payment_utxo.value)
                  |> value.flatten()
              (asset_policy, asset_name, amount)
            }

          // Verifies that the payment UTXO contains the correct token asset (by policy and name)
          // and that the amount is at least the expected amount specified in the datum.
          let is_sender_payment_utxo_value_correct =
            AssetClass { policy: asset_policy, name: asset_name } == datum.info.token.asset_class && amount >= datum.info.token.amount

          // Returns true if both the address and the token payment conditions are met.
          is_sender_payment_utxo_address_correct? && is_sender_payment_utxo_value_correct?
        }
      }

    // Checks if the correct token is being burned (negative minted quantity)
    // and matches the control asset class details.
    let is_token_burned =
      minted_quantity == -1 && minted_policy == datum.control_asset_class.policy && minted_name == datum.control_asset_class.name

    // The order is valid if both the redeemer logic is valid and the token is correctly burned.
    is_redeemer_valid? && is_token_burned?
  }

  /// `mint` function
  ///
  /// This function validates minting policies associated with a control token based on a provided
  /// redeemer and context.
  ///
  /// # Parameters:
  /// - `_redeemer`: Data related to the action on the control token.
  ///                Currently, this is not used in the function.
  /// - `context`: Provides the surrounding context of the transaction, including details about
  ///              minted tokens, signatories, etc.
  ///
  /// # Returns:
  /// - `true` if the minting policy for the control token is valid, `false` otherwise.
  fn mint(_redeemer: Data, context: ScriptContext) -> Bool {
    // - Extracts minting information to determine what token is being minted/burned, the policy
    //   it's associated with, and the quantity.
    let (minted_policy, minted_name, minted_quantity) =
      utils.get_minting_info(context.transaction)

    // - Checks if a token is being burned. If so, returns `true` immediately, signaling that the
    //   transaction is valid.
    let is_token_burned = minted_quantity == -1
    if is_token_burned {
      True
    } else {
      // - If not burning, the function checks the following:
      // 1. That there's exactly one UTXO output associated with a particular script address.
      expect [order_utxo] =
        context.transaction.outputs
          |> transaction.find_script_outputs(minted_policy)

      let OrderDatum { info, control_asset_class } =
        utils.to_order_datum(order_utxo.datum)

      // 2. Ensures that the signer of the transaction is indeed the sender.
      let is_signer_sender =
        list.has(
          context.transaction.extra_signatories,
          info.sender_payment_hash,
        )

      // 3. Validates that the control token is being correctly paid to the script.
      let is_control_token_paid_to_the_script =
        value.quantity_of(order_utxo.value, minted_policy, minted_name) == minted_quantity

      // 4. Ensures that the token amount in the datum is positive.
      let is_datum_payment_valid = info.token.amount > 0

      // 5. Validates that a new token is being minted with the correct policy, name, and quantity.
      let is_minting_valid =
        minted_quantity == 1 && minted_policy == control_asset_class.policy && minted_name == control_asset_class.name

      is_minting_valid? && is_signer_sender? && is_datum_payment_valid? && is_control_token_paid_to_the_script?
    }
  }
}
