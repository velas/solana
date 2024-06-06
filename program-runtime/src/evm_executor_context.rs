use std::{fmt, marker::PhantomData};

use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeTuple as _,
    Deserialize, Deserializer, Serialize, Serializer,
};

pub const MAX_EVM_BLOCKHASHES: usize = 256;
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockHashEvm {
    #[serde(with = "BlockHashEvm")]
    hashes: [evm_state::H256; MAX_EVM_BLOCKHASHES],
}

impl BlockHashEvm {
    pub fn new() -> BlockHashEvm {
        BlockHashEvm {
            hashes: [evm_state::H256::zero(); MAX_EVM_BLOCKHASHES],
        }
    }
    pub fn get_hashes(&self) -> &[evm_state::H256; MAX_EVM_BLOCKHASHES] {
        &self.hashes
    }

    pub fn insert_hash(&mut self, hash: evm_state::H256) {
        let new_hashes = self.hashes;
        self.hashes[0..MAX_EVM_BLOCKHASHES - 1]
            .copy_from_slice(&new_hashes[1..MAX_EVM_BLOCKHASHES]);
        self.hashes[MAX_EVM_BLOCKHASHES - 1] = hash
    }

    fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<[evm_state::H256; MAX_EVM_BLOCKHASHES], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor<T> {
            element: PhantomData<T>,
        }
        impl<'de, T> Visitor<'de> for ArrayVisitor<T>
        where
            T: Default + Copy + Deserialize<'de>,
        {
            type Value = [T; MAX_EVM_BLOCKHASHES];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(concat!("an array of length ", 256))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<[T; MAX_EVM_BLOCKHASHES], A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = [T::default(); MAX_EVM_BLOCKHASHES];
                for (i, item) in arr.iter_mut().enumerate().take(MAX_EVM_BLOCKHASHES) {
                    *item = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }

        let visitor = ArrayVisitor {
            element: PhantomData,
        };
        deserializer.deserialize_tuple(MAX_EVM_BLOCKHASHES, visitor)
    }

    fn serialize<S>(
        data: &[evm_state::H256; MAX_EVM_BLOCKHASHES],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(data.len())?;
        for elem in &data[..] {
            seq.serialize_element(elem)?;
        }
        seq.end()
    }
}

impl Default for BlockHashEvm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use evm_state::H256;

    use super::*;

    #[test]
    fn test_evm_blockhaheshes() {
        let mut blockhash_queue = BlockHashEvm::new();
        assert_eq!(
            blockhash_queue.get_hashes(),
            &[H256::zero(); MAX_EVM_BLOCKHASHES]
        );
        let hash1 = H256::repeat_byte(1);
        blockhash_queue.insert_hash(hash1);
        for hash in &blockhash_queue.get_hashes()[..MAX_EVM_BLOCKHASHES - 1] {
            assert_eq!(*hash, H256::zero())
        }
        assert_eq!(blockhash_queue.get_hashes()[MAX_EVM_BLOCKHASHES - 1], hash1);

        for i in 0..MAX_EVM_BLOCKHASHES {
            let hash1 = H256::repeat_byte(i as u8);
            blockhash_queue.insert_hash(hash1)
        }

        for (i, hash) in blockhash_queue.get_hashes()[..MAX_EVM_BLOCKHASHES]
            .iter()
            .enumerate()
        {
            let hash1 = H256::repeat_byte(i as u8);
            assert_eq!(*hash, hash1)
        }
    }
}
