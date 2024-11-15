use crate::pallas_codec::minicbor::to_vec;
use crate::pallas_primitives::byron;

pub struct PolicyParams {
    constant: u64,
    size_coeficient: u64,
}

impl Default for PolicyParams {
    fn default() -> Self {
        Self {
            constant: 155_381_000_000_000u64,
            size_coeficient: 43_946_000_000u64,
        }
    }
}

pub fn compute_linear_fee_policy(tx_size: u64, params: &PolicyParams) -> u64 {
    let nanos = params.constant + (tx_size * params.size_coeficient);

    let loves = nanos / 1_000_000_000;

    let rem = match nanos % 1_000_000_000 {
        0 => 0u64,
        _ => 1u64,
    };

    loves + rem
}

pub fn compute_byron_fee(tx: &byron::MintedTxPayload, params: Option<&PolicyParams>) -> u64 {
    let tx_size = to_vec(tx).unwrap().len();

    match params {
        Some(params) => compute_linear_fee_policy(tx_size as u64, params),
        None => compute_linear_fee_policy(tx_size as u64, &PolicyParams::default()),
    }
}
