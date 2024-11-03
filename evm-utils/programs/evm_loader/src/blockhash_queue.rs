//! Store the blockhashes for the last `MAX_BLOCKHASHES` blocks.
//!
//!
//!
const MAX_BLOCKHASHES: usize = 256;
use {
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
    evm_state::H256 as Hash,
    serde::{ser::SerializeStruct, Serialize},
    solana_sdk::clock::Slot,
};

#[derive(
    BorshSerialize, BorshDeserialize, BorshSchema, Clone, Debug, PartialEq, Eq, Ord, PartialOrd,
)]
pub struct BlockhashQueue {
    blockhashes: [Hash; MAX_BLOCKHASHES],
    last_slot: Slot,
}

impl Serialize for BlockhashQueue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut ser_struct = serializer.serialize_struct("BlockhashQueue", 2)?;
        let blockhashes = self
            .blockhashes
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        ser_struct.serialize_field("blockhashes", &blockhashes)?;
        ser_struct.serialize_field("last_slot", &self.last_slot)?;
        ser_struct.end()
    }
}

impl BlockhashQueue {
    pub fn new() -> Self {
        Self {
            blockhashes: [Hash::default(); MAX_BLOCKHASHES],
            last_slot: 0,
        }
    }
    /// Push new hash to blockhashes queue,
    /// Ignore if the same hash is last in the queue.
    pub fn push(&mut self, new_hash: Hash, slot: Slot) {
        assert!(self.last_slot <= slot);
        // skip saving same hash
        if self.blockhashes[255] == new_hash {
            return;
        }
        // If it is new slot - shift all blockhashes and update last_slot
        if self.last_slot < slot {
            // move all array elements one step forward
            self.blockhashes.rotate_left(1);
            self.last_slot = slot;
        }
        // Also update the last blockhash
        self.blockhashes[255] = new_hash;
    }
    pub fn get_hashes(&self) -> &[Hash; MAX_BLOCKHASHES] {
        &self.blockhashes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bq_persist_multiple_hashes() {
        let mut blockhash_queue = BlockhashQueue::new();

        // We insert 10 blocks
        const TOTAL_BLOCK_TO_INSERT: u8 = 10;

        // Index is calculated based on current block, it is offset from the end of the array.
        // This method is only usefull inside tests, and should be only used when slot is is monotonic.
        fn get_index(slot: Slot) -> usize {
            let current_block = TOTAL_BLOCK_TO_INSERT as Slot;
            MAX_BLOCKHASHES - (current_block - slot) as usize
        }

        for i in 0..TOTAL_BLOCK_TO_INSERT {
            blockhash_queue.push(Hash::repeat_byte(i), i as Slot);
        }

        assert_eq!(
            blockhash_queue.get_hashes()[get_index(0)],
            Hash::repeat_byte(0)
        );
        assert_eq!(
            blockhash_queue.get_hashes()[get_index(1)],
            Hash::repeat_byte(1)
        );
        assert_eq!(
            blockhash_queue.get_hashes()[get_index(2)],
            Hash::repeat_byte(2)
        );
        assert_eq!(
            blockhash_queue.get_hashes()[get_index(3)],
            Hash::repeat_byte(3)
        );
    }

    #[test]
    fn test_bq_persist_update_same_slot() {
        let mut blockhash_queue = BlockhashQueue::new();
        blockhash_queue.push(Hash::repeat_byte(0), 0 as Slot);
        blockhash_queue.push(Hash::repeat_byte(1), 1 as Slot);
        blockhash_queue.push(Hash::repeat_byte(2), 2 as Slot);
        //...
        blockhash_queue.push(Hash::repeat_byte(3), 3 as Slot);
        // println!("{:?}", blockhash_queue.get_hashes());
        // panic! {};
        assert_eq!(blockhash_queue.get_hashes()[255 - 3], Hash::repeat_byte(0));
        assert_eq!(blockhash_queue.get_hashes()[255 - 2], Hash::repeat_byte(1));
        assert_eq!(blockhash_queue.get_hashes()[255 - 1], Hash::repeat_byte(2));
        assert_eq!(blockhash_queue.get_hashes()[255], Hash::repeat_byte(3));
        // Update for same slot
        blockhash_queue.push(Hash::repeat_byte(33), 3 as Slot);

        blockhash_queue.push(Hash::repeat_byte(33), 4 as Slot); // prevent pushing same hash on different slot
        assert_eq!(blockhash_queue.get_hashes()[255 - 3], Hash::repeat_byte(0));
        assert_eq!(blockhash_queue.get_hashes()[255 - 2], Hash::repeat_byte(1));
        assert_eq!(blockhash_queue.get_hashes()[255 - 1], Hash::repeat_byte(2));
        assert_eq!(blockhash_queue.get_hashes()[255], Hash::repeat_byte(33));
    }
}
