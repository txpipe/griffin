// Brought from pallas-applying/tests/
use pallas_applying::{
    UTxOs,
    utils::{ValidationError, BabbageProtParams},
};
use crate::types::UTxOError::{self, *};
use pallas_codec::minicbor::encode;
use pallas_primitives::{
    alonzo::Value,
    babbage::{
        MintedDatumOption, MintedPostAlonzoTransactionOutput, MintedScriptRef,
        MintedTransactionBody, MintedTransactionOutput, MintedTx as BabbageMintedTx,
        PseudoTransactionOutput, Tx as BabbageTx,
    },
};
use pallas_traverse::{MultiEraInput, MultiEraOutput};
use alloc::{
    borrow::Cow, vec::Vec, vec,
    string::String,
    boxed::Box,
};
use core::iter::zip;
use pallas_codec::utils::{Bytes, CborWrap};

impl From<ValidationError> for UTxOError {
    fn from(err: ValidationError) -> UTxOError {
        match err {
            ValidationError::Babbage(err) => UTxOError::Babbage(err),
            _ => Fail,
        }
    }
}

pub fn babbage_tx_to_cbor(tx: &BabbageTx) -> Vec<u8> {
    let mut tx_buf: Vec<u8> = Vec::new();
    let _ = encode(tx, &mut tx_buf);

    tx_buf
}

pub fn babbage_minted_tx_from_cbor(tx_cbor: &[u8]) -> BabbageMintedTx<'_> {
    pallas_codec::minicbor::decode::<BabbageMintedTx>(&tx_cbor[..]).unwrap()
}

pub fn mk_utxo_for_babbage_tx<'a>(
    tx_body: &MintedTransactionBody,
    tx_outs_info: &'a [(
        String, // address in string format
        Value,
        Option<MintedDatumOption>,
        Option<CborWrap<MintedScriptRef>>,
    )],
) -> UTxOs<'a> {
    let mut utxos: UTxOs = UTxOs::new();
    for (tx_in, (addr, val, datum_opt, script_ref)) in zip(tx_body.inputs.clone(), tx_outs_info) {
        let multi_era_in: MultiEraInput =
            MultiEraInput::AlonzoCompatible(Box::new(Cow::Owned(tx_in)));
        let address_bytes: Bytes = match hex::decode(addr) {
            Ok(bytes_vec) => Bytes::from(bytes_vec),
            _ => panic!("Unable to decode input address"),
        };
        let tx_out: MintedTransactionOutput =
            PseudoTransactionOutput::PostAlonzo(MintedPostAlonzoTransactionOutput {
                address: address_bytes,
                value: val.clone(),
                datum_option: datum_opt.clone(),
                script_ref: script_ref.clone(),
            });
        let multi_era_out: MultiEraOutput = MultiEraOutput::Babbage(Box::new(Cow::Owned(tx_out)));
        utxos.insert(multi_era_in, multi_era_out);
    }

    utxos
}

// originally `mk_mainnet_params_epoch_380`
pub fn mk_prot_params() -> BabbageProtParams {
    use pallas_primitives::babbage::{
        CostModels, ExUnitPrices, ExUnits, Nonce, NonceVariant, RationalNumber,
    };
    
    BabbageProtParams {
        minfee_a: 0,
        minfee_b: 0,
        max_block_body_size: 90112,
        max_transaction_size: 16384,
        max_block_header_size: 1100,
        key_deposit: 2000000,
        pool_deposit: 500000000,
        maximum_epoch: 18,
        desired_number_of_stake_pools: 500,
        pool_pledge_influence: RationalNumber {
            numerator: 3,
            denominator: 10,
        },
        expansion_rate: RationalNumber {
            numerator: 3,
            denominator: 1000,
        },
        treasury_growth_rate: RationalNumber {
            numerator: 2,
            denominator: 10,
        },
        decentralization_constant: RationalNumber {
            numerator: 0,
            denominator: 1,
        },
        extra_entropy: Nonce {
            variant: NonceVariant::NeutralNonce,
            hash: None,
        },
        protocol_version: (7, 0),
        min_pool_cost: 340000000,
        ada_per_utxo_byte: 1,
        cost_models_for_script_languages: CostModels {
            plutus_v1: Some(vec![
                205665, 812, 1, 1, 1000, 571, 0, 1, 1000, 24177, 4, 1, 1000, 32, 117366, 10475,
                4, 23000, 100, 23000, 100, 23000, 100, 23000, 100, 23000, 100, 23000, 100, 100,
                100, 23000, 100, 19537, 32, 175354, 32, 46417, 4, 221973, 511, 0, 1, 89141, 32,
                497525, 14068, 4, 2, 196500, 453240, 220, 0, 1, 1, 1000, 28662, 4, 2, 245000,
                216773, 62, 1, 1060367, 12586, 1, 208512, 421, 1, 187000, 1000, 52998, 1,
                80436, 32, 43249, 32, 1000, 32, 80556, 1, 57667, 4, 1000, 10, 197145, 156, 1,
                197145, 156, 1, 204924, 473, 1, 208896, 511, 1, 52467, 32, 64832, 32, 65493,
                32, 22558, 32, 16563, 32, 76511, 32, 196500, 453240, 220, 0, 1, 1, 69522,
                11687, 0, 1, 60091, 32, 196500, 453240, 220, 0, 1, 1, 196500, 453240, 220, 0,
                1, 1, 806990, 30482, 4, 1927926, 82523, 4, 265318, 0, 4, 0, 85931, 32, 205665,
                812, 1, 1, 41182, 32, 212342, 32, 31220, 32, 32696, 32, 43357, 32, 32247, 32,
                38314, 32, 9462713, 1021, 10,
            ]),

            plutus_v2: Some(vec![
                205665,
                812,
                1,
                1,
                1000,
                571,
                0,
                1,
                1000,
                24177,
                4,
                1,
                1000,
                32,
                117366,
                10475,
                4,
                23000,
                100,
                23000,
                100,
                23000,
                100,
                23000,
                100,
                23000,
                100,
                23000,
                100,
                100,
                100,
                23000,
                100,
                19537,
                32,
                175354,
                32,
                46417,
                4,
                221973,
                511,
                0,
                1,
                89141,
                32,
                497525,
                14068,
                4,
                2,
                196500,
                453240,
                220,
                0,
                1,
                1,
                1000,
                28662,
                4,
                2,
                245000,
                216773,
                62,
                1,
                1060367,
                12586,
                1,
                208512,
                421,
                1,
                187000,
                1000,
                52998,
                1,
                80436,
                32,
                43249,
                32,
                1000,
                32,
                80556,
                1,
                57667,
                4,
                1000,
                10,
                197145,
                156,
                1,
                197145,
                156,
                1,
                204924,
                473,
                1,
                208896,
                511,
                1,
                52467,
                32,
                64832,
                32,
                65493,
                32,
                22558,
                32,
                16563,
                32,
                76511,
                32,
                196500,
                453240,
                220,
                0,
                1,
                1,
                69522,
                11687,
                0,
                1,
                60091,
                32,
                196500,
                453240,
                220,
                0,
                1,
                1,
                196500,
                453240,
                220,
                0,
                1,
                1,
                1159724,
                392670,
                0,
                2,
                806990,
                30482,
                4,
                1927926,
                82523,
                4,
                265318,
                0,
                4,
                0,
                85931,
                32,
                205665,
                812,
                1,
                1,
                41182,
                32,
                212342,
                32,
                31220,
                32,
                32696,
                32,
                43357,
                32,
                32247,
                32,
                38314,
                32,
                20000000000,
                20000000000,
                9462713,
                1021,
                10,
                20000000000,
                0,
                20000000000,
            ]),
        },
        execution_costs: ExUnitPrices {
            mem_price: RationalNumber {
                numerator: 577,
                denominator: 10000,
            },
            step_price: RationalNumber {
                numerator: 721,
                denominator: 10000000,
            },
        },
        max_tx_ex_units: ExUnits {
            mem: 14000000,
            steps: 10000000000,
        },
        max_block_ex_units: ExUnits {
            mem: 62000000,
            steps: 40000000000,
        },
        max_value_size: 5000,
        collateral_percentage: 150,
        max_collateral_inputs: 3,
    }
}
