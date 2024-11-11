//! Ledger primitives and cbor codec for the Cardano eras

// FRANCO:
// #![cfg_attr(not(feature = "std"), no_std)]
#![no_std]

// FRANCO: NO DISPONIBLE EN STABLE RUST, REQUIERE NIGHTLY BUILD:
// error[E0554]: `#![feature]` may not be used on the stable release channel
// #![feature(error_in_core)]

#[macro_use]
extern crate alloc;

mod framework;

pub mod alonzo;
pub mod babbage;
pub mod byron;
pub mod conway;

pub use framework::*;
