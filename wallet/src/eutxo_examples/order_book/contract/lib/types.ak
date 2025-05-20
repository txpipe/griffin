use aiken/hash.{Blake2b_224, Hash}
use aiken/transaction/credential.{Script, VerificationKey}
use aiken/transaction/value.{AssetName, PolicyId}

// This module defines the primary data types used in the order contract. These types model the
// structure of an order, the possible actions (redeemers) that can be taken on the order,
// the information associated with an order, and the unique class of an asset.

/// Represents the datum used in the order contract.
///
/// # Fields:
/// * `info`                - General information about the order.
/// * `control_asset_class` - Policy ID and asset name of the control token.
pub type OrderDatum {
  info: OrderInfo,
  control_asset_class: AssetClass,
}

/// Represents the different actions that can be taken to redeem an order.
///
/// # Variants:
/// * `CancelOrder`  - Action to cancel the order.
/// * `ResolveOrder` - Action to resolve the order.
pub type OrderRedeemer {
  CancelOrder
  ResolveOrder
}

/// Contains information about an order.
///
/// # Fields:
/// * `sender_payment_hash` - The payment address of the sender in the order.
/// * `sender_staking_hash` - The staking address of the sender in the order.
/// * `token`               - The tokens being handled in the transaction (receiver's payment).
pub type OrderInfo {
  sender_payment_hash: PubKeyHash,
  token: DatumValue,
}

/// Represents a unique class of asset in the Cardano network.
///
/// Each asset on the Cardano network is uniquely identified by its Policy ID and its Asset Name.
/// The combination of a Policy ID and an Asset Name is known as an Asset Class.
///
/// # Fields:
/// * `policy_id`   - The unique identifier of the monetary policy that governs the asset.
/// * `asset_name`  - The unique name of the asset within the policy.
pub type AssetClass {
  policy: PolicyId,
  name: AssetName,
}

/// Represents the value information stored in the datum of the Order UTxO.
pub type DatumValue {
  asset_class: AssetClass,
  amount: Int,
}

/// Represents the address in an order contract.
/// This is a hash of the sender's (or receiver) verification key.
pub type PubKeyHash =
  Hash<Blake2b_224, VerificationKey>

/// Represents the script address in an order contract.
/// This is a hash of the script.
pub type ScriptAddress =
  Hash<Blake2b_224, Script>
