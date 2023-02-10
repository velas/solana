use std::{collections::HashMap, path::Path};

use anyhow::*;
use chrono::{DateTime, Utc};
use evm_state::BlockNum;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct BlockDto {
    number: u64,
    timestamp: Option<DateTime<Utc>>,
    unixtime: Option<u64>,
}

/// FIXME: Source timestamp file exported with Time Zone error
pub const HR_TIMESTAMP: i64 = 60 * 60;

pub fn load_timestamps(
    path: impl AsRef<Path>,
    timestamp_offset: i64,
) -> Result<HashMap<BlockNum, u64>> {
    let timestamps = std::fs::read_to_string(path).unwrap();

    let result: HashMap<BlockNum, u64> = serde_json::from_str::<Vec<BlockDto>>(&timestamps)
        .unwrap()
        .into_iter()
        .map(|block| {
            let block_number = block.number;

            // Extract time from "unixtime" prop., or try to parse ISO 8601 "timestamp" prop.
            let time = block
                .unixtime
                .or_else(|| {
                    block
                        .timestamp
                        .map(|t| (t.timestamp() + timestamp_offset) as u64)
                })
                .unwrap();

            (block_number, time)
        })
        .collect();

    Ok(result)
}
