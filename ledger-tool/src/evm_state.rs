use std::{borrow::Borrow, collections::HashSet, marker::PhantomData, path::Path};

use anyhow::{anyhow, Result};
use clap::{value_t_or_exit, App, AppSettings, Arg, ArgMatches, SubCommand};
use log::*;

use evm_state::{types::Account, H256, U256};
use evm_state::{Storage, DB as RocksDB};
use rlp::{Decodable, Rlp};
use triedb::{
    empty_trie_hash,
    merkle::{MerkleNode, MerkleValue},
};

pub trait EvmStateSubCommand {
    fn evm_state_subcommand(self) -> Self;
}

impl EvmStateSubCommand for App<'_, '_> {
    fn evm_state_subcommand(self) -> Self {
        self.subcommand(
            SubCommand::with_name("evm_state")
                .about("EVM state utilities")
                .setting(AppSettings::ArgRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("purge")
                        .about("Cleanup EVM state data that unreachable from state root")
                        .arg(
                            Arg::with_name("root")
                                .long("root")
                                .takes_value(true)
                                .required(true)
                                .help("EVM state root hash"),
                        )
                        .arg(
                            Arg::with_name("dry_run")
                                .long("dry-run")
                                .help("Do nothing, just collect hashes and print them"),
                        ),
                ),
        )
    }
}

pub fn process_evm_state_command(ledger_path: &Path, matches: &ArgMatches<'_>) -> Result<()> {
    match matches.subcommand() {
        ("purge", Some(matches)) => {
            let root = value_t_or_exit!(matches, "root", H256);
            info!("EVM state root {:?}", root);
            let is_dry_run = matches.is_present("dry_run");

            if is_dry_run {
                info!("Dry run, do nothing after collecting keys ...");
            }

            let evm_state_path = ledger_path.join("evm-state");
            let storage = Storage::open_persistent(evm_state_path)?;
            assert!(storage.check_root_exist(root));
            let db = storage.db();

            let mut accounts_walker = KeyTracker::<_, Account>::new(db);
            accounts_walker.collect_keys(root)?;

            let mut storage_walker = KeyTracker::<_, U256>::new(db);
            for storage_root in accounts_walker.sub_roots {
                storage_walker.collect_keys(storage_root)?;
            }

            if is_dry_run {
                info!("Total [Account]s keys {}", accounts_walker.keys.len());
                info!("Total [Storage]s keys {}", storage_walker.keys.len());
            } else {
                todo!("remove keys")
            }
        }
        unhandled => panic!("Unhandled {:?}", unhandled),
    }
    Ok(())
}

struct KeyTracker<DB, T> {
    db: DB,
    keys: HashSet<H256>,
    sub_roots: HashSet<H256>,
    _data_marker: PhantomData<T>,
}

impl<DB, T> KeyTracker<DB, T> {
    fn new(db: DB) -> Self {
        Self {
            db,
            keys: HashSet::new(),
            sub_roots: HashSet::new(),
            _data_marker: PhantomData,
        }
    }
}

impl<DB, T> KeyTracker<DB, T>
where
    DB: Borrow<RocksDB>,
    T: Decodable + HasSubTrie,
{
    fn collect_keys(&mut self, hash: H256) -> Result<()> {
        if hash != empty_trie_hash() {
            let db = self.db.borrow();
            let bytes = db
                .get(hash)?
                .ok_or_else(|| anyhow!("hash {:?} not found in database", hash))?;
            trace!("{:?} raw bytes: {:?}", hash, bytes);
            let rlp = Rlp::new(bytes.as_slice());
            trace!("{:?} rlp: {:?}", hash, rlp);
            let node = MerkleNode::decode(&rlp)?;
            debug!("{:?} node: {:?}", hash, node);

            self.keys.insert(hash);
            self.process_node(node)?;
        } else {
            debug!("skip empty trie");
        }
        Ok(())
    }

    fn process_node(&mut self, node: MerkleNode) -> Result<()> {
        match node {
            MerkleNode::Leaf(_nibbles, data) => {
                let rlp = Rlp::new(data);
                let t = T::decode(&rlp)?;
                if let Some(sub_root) = t.sub_root() {
                    self.sub_roots.insert(sub_root);
                }
            }
            MerkleNode::Extension(_nibbles, value) => self.process_value(value)?,
            MerkleNode::Branch(values, data) => {
                for value in values {
                    self.process_value(value)?;
                }
                if let Some(data) = data {
                    let rlp = Rlp::new(data);
                    let t = T::decode(&rlp)?;
                    if let Some(sub_root) = t.sub_root() {
                        self.sub_roots.insert(sub_root);
                    }
                }
            }
        }

        Ok(())
    }

    fn process_value(&mut self, value: MerkleValue) -> Result<()> {
        match value {
            MerkleValue::Empty => Ok(()),
            MerkleValue::Full(node) => self.process_node(*node),
            MerkleValue::Hash(hash) => self.collect_keys(hash),
        }
    }
}

trait HasSubTrie {
    fn sub_root(&self) -> Option<H256>;
}

impl HasSubTrie for Account {
    fn sub_root(&self) -> Option<H256> {
        Some(self.storage_root)
    }
}

impl HasSubTrie for U256 {
    fn sub_root(&self) -> Option<H256> {
        None
    }
}
