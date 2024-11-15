use crate::pallas_traverse::{wellknown::GenesisValues, MultiEraBlock};

pub type Epoch = u64;

pub type Slot = u64;

pub type SubSlot = u64;

#[inline]
fn compute_linear_timestamp(
    known_slot: u64,
    known_time: u64,
    slot_length: u64,
    query_slot: u64,
) -> u64 {
    known_time + (query_slot - known_slot) * slot_length
}

#[inline]
fn compute_era_epoch(era_slot: Slot, era_slot_length: u64, era_epoch_length: u64) -> (Epoch, Slot) {
    assert!(
        era_epoch_length > 0,
        "epoch length needs to be greater than zero"
    );

    let epoch = (era_slot * era_slot_length) / era_epoch_length;
    let reminder = era_slot % era_epoch_length;

    (epoch, reminder)
}

pub fn compute_absolute_slot_within_era(
    sub_era_epoch: Epoch,
    sub_epoch_slot: Slot,
    era_epoch_length: u32,
    era_slot_length: u32,
) -> u64 {
    ((sub_era_epoch * era_epoch_length as u64) / era_slot_length as u64) + sub_epoch_slot
}

impl GenesisValues {
    pub fn shelley_start_epoch(&self) -> Epoch {
        let (epoch, _) = compute_era_epoch(
            self.shelley_known_slot,
            self.byron_slot_length as u64,
            self.byron_epoch_length as u64,
        );

        epoch
    }

    pub fn slot_to_wallclock(&self, slot: u64) -> u64 {
        if slot < self.shelley_known_slot {
            compute_linear_timestamp(
                self.byron_known_slot,
                self.byron_known_time,
                self.byron_slot_length as u64,
                slot,
            )
        } else {
            compute_linear_timestamp(
                self.shelley_known_slot,
                self.shelley_known_time,
                self.shelley_slot_length as u64,
                slot,
            )
        }
    }

    pub fn absolute_slot_to_relative(&self, slot: u64) -> (u64, u64) {
        if slot < self.shelley_known_slot {
            compute_era_epoch(
                slot,
                self.byron_slot_length as u64,
                self.byron_epoch_length as u64,
            )
        } else {
            let era_slot = slot - self.shelley_known_slot;

            let (era_epoch, reminder) = compute_era_epoch(
                era_slot,
                self.shelley_slot_length as u64,
                self.shelley_epoch_length as u64,
            );

            (self.shelley_start_epoch() + era_epoch, reminder)
        }
    }

    pub fn relative_slot_to_absolute(&self, epoch: Epoch, slot: Slot) -> Slot {
        let shelley_start_epoch = self.shelley_start_epoch();

        if epoch < shelley_start_epoch {
            compute_absolute_slot_within_era(
                epoch,
                slot,
                self.byron_epoch_length,
                self.byron_slot_length,
            )
        } else {
            let byron_slots = compute_absolute_slot_within_era(
                shelley_start_epoch,
                0,
                self.byron_epoch_length,
                self.byron_slot_length,
            );

            let shelley_slots = compute_absolute_slot_within_era(
                epoch - shelley_start_epoch,
                slot,
                self.shelley_epoch_length,
                self.shelley_slot_length,
            );

            byron_slots + shelley_slots
        }
    }
}

impl<'a> MultiEraBlock<'a> {
    pub fn epoch(&self, genesis: &GenesisValues) -> (Epoch, SubSlot) {
        match self {
            MultiEraBlock::EpochBoundary(x) => (x.header.consensus_data.epoch_id, 0),
            MultiEraBlock::Byron(x) => (
                x.header.consensus_data.0.epoch,
                x.header.consensus_data.0.slot,
            ),
            MultiEraBlock::AlonzoCompatible(x, _) => {
                genesis.absolute_slot_to_relative(x.header.header_body.slot)
            }
            MultiEraBlock::Babbage(x) => {
                genesis.absolute_slot_to_relative(x.header.header_body.slot)
            }
            MultiEraBlock::Conway(x) => {
                genesis.absolute_slot_to_relative(x.header.header_body.slot)
            }
        }
    }

    /// Computes the unix timestamp for the slot of the tx
    pub fn wallclock(&self, genesis: &GenesisValues) -> u64 {
        let slot = self.slot();
        genesis.slot_to_wallclock(slot)
    }
}
