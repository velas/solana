use lazy_static::lazy_static;
use solana_sdk::{
    clock::Slot,
    hash::{Hash, Hasher},
    pubkey::Pubkey,
};
use std::collections::{HashMap, HashSet};

pub mod instructions_sysvar_enabled {
    solana_sdk::declare_id!("EnvhHCLvg55P7PDtbvR1NwuTuAeodqpusV3MR5QEK8gs");
}

pub mod secp256k1_program_enabled {
    solana_sdk::declare_id!("E3PHP7w8kB7np3CTQ1qQ2tW3KCtjRSXBQgW9vM2mWv2Y");
}

pub mod consistent_recent_blockhashes_sysvar {
    solana_sdk::declare_id!("3h1BQWPDS5veRsq6mDBWruEpgPxRJkfwGexg5iiQ9mYg");
}

pub mod deprecate_rewards_sysvar {
    solana_sdk::declare_id!("GaBtBJvmS4Arjj5W1NmFcyvPjsHN38UGYDq2MDwbs9Qu");
}

pub mod pico_inflation {
    solana_sdk::declare_id!("4RWNif6C2WCNiKVW7otP4G7dkmkHGyKQWRpuZ1pxKU5m");
}

pub mod full_inflation {
    pub mod devnet_and_testnet_velas_mainnet {
        solana_sdk::declare_id!("DT4n6ABDqs6w4bnfwrXT9rsprcPf6cdDga1egctaPkLC");
    }

    pub mod mainnet {
        pub mod certusone {
            pub mod vote {
                solana_sdk::declare_id!("BzBBveUDymEYoYzcMWNQCx3cd4jQs7puaVFHLtsbB6fm");
            }
            pub mod enable {
                solana_sdk::declare_id!("7XRJcS5Ud5vxGB54JbK9N2vBZVwnwdBNeJW1ibRgD9gx");
            }
        }
    }
}

pub mod spl_token_v2_multisig_fix {
    solana_sdk::declare_id!("E5JiFDQCwyC6QfT9REFyMpfK2mHcmv1GUDySU1Ue7TYv");
}

pub mod no_overflow_rent_distribution {
    solana_sdk::declare_id!("4kpdyrcj5jS47CZb2oJGfVxjYbsMm2Kx97gFyZrxxwXz");
}

pub mod stake_program_v2 {
    solana_sdk::declare_id!("Gvd9gGJZDHGMNf1b3jkxrfBQSR5etrfTQSBNKCvLSFJN");
}

pub mod rewrite_stake {
    solana_sdk::declare_id!("6ap2eGy7wx5JmsWUmQ5sHwEWrFSDUxSti2k5Hbfv5BZG");
}

pub mod filter_stake_delegation_accounts {
    solana_sdk::declare_id!("GE7fRxmW46K6EmCD9AMZSbnaJ2e3LfqCZzdHi9hmYAgi");
}

pub mod bpf_loader_upgradeable_program {
    solana_sdk::declare_id!("FbhK8HN9qvNHvJcoFVHAEUCNkagHvu7DTWzdnLuVQ5u4");
}

pub mod stake_program_v3 {
    solana_sdk::declare_id!("Ego6nTu7WsBcZBvVqJQKp6Yku2N3mrfG8oYCfaLZkAeK");
}

pub mod require_custodian_for_locked_stake_authorize {
    solana_sdk::declare_id!("D4jsDcXaqdW8tDAWn8H4R25Cdns2YwLneujSL1zvjW6R");
}

pub mod spl_token_v2_self_transfer_fix {
    solana_sdk::declare_id!("BL99GYhdjjcv6ys22C9wPgn2aTVERDbPHHo4NbS3hgp7");
}

pub mod warp_timestamp_again {
    solana_sdk::declare_id!("GvDsGDkH5gyzwpDhxNixx8vtx1kwYHH13RiNAPw27zXb");
}

pub mod check_init_vote_data {
    solana_sdk::declare_id!("3ccR6QpxGYsAbWyfevEtBNGfWV4xBffxRj2tD6A9i39F");
}

pub mod check_program_owner {
    solana_sdk::declare_id!("5XnbR5Es9YXEARRuP6mdvoxiW3hx5atNNeBmwVd8P3QD");
}

pub mod cpi_share_ro_and_exec_accounts {
    solana_sdk::declare_id!("6VgVBi3uRVqp56TtEwNou8idgdmhCD1aYqX8FaJ1fnJb");
}

pub mod skip_ro_deserialization {
    solana_sdk::declare_id!("6Sw5JV84f7QkDe8gvRxpcPWFnPpfpgEnNziiy8sELaCp");
}

pub mod require_stake_for_gossip {
    solana_sdk::declare_id!("EV8cfTBZfhjNH23qg7xz4TL95f4vKLGoNuG5gJJG85WY");
}

pub mod cpi_data_cost {
    solana_sdk::declare_id!("CuYeffE36Bed4qExko1XwUDHB2b6TJ9pwphXw52Nm9UB");
}

pub mod upgradeable_close_instruction {
    solana_sdk::declare_id!("8CiKcDAct4LY4FZgzTv2tcAi1PkNW2P1JFzaS28tpFzB");
}

pub mod demote_sysvar_write_locks {
    solana_sdk::declare_id!("6LDeGYz9iqbscuLrMYpZxeifFZWDzXL7n7zS6syaCDJ8");
}

pub mod sysvar_via_syscall {
    solana_sdk::declare_id!("2bfZ6cxMn5yJ5cf3T8J3zSoraYPe9V9iMSab1gNiRERr");
}

pub mod check_duplicates_by_hash {
    solana_sdk::declare_id!("AjSWo5fdpbo2Xy2G8Xbjhythe42MQci3CV8FuJ9cpi9d");
}

pub mod enforce_aligned_host_addrs {
    solana_sdk::declare_id!("5GDsuYGNKRRKE2tTpid7aGRixfryAVBz2MPHzSJexwyp");
}
pub mod set_upgrade_authority_via_cpi_enabled {
    solana_sdk::declare_id!("3n34oY4kEma7jNGGsu4btRteisnqqHGmSEZNJpz3A8cU");
}

pub mod update_data_on_realloc {
    solana_sdk::declare_id!("23wrJ1vCGMbugM14C5vgXxP1trJbKSzK52MnMzWBtQQ4");
}

pub mod keccak256_syscall_enabled {
    solana_sdk::declare_id!("DtDVADxBHPQpPUuXunL4tRik4fx9YiSQTHa5H1hXHksc");
}

pub mod stake_program_v4 {
    solana_sdk::declare_id!("cug7ESsYA4ma7iE1y4qgi5zsdKyo6KJ1NyS5K4CVEE3");
}

pub mod system_transfer_zero_check {
    solana_sdk::declare_id!("EqohBJpJsJym3qAJ3N7AH35c4u2rfS5yYvS693ThYTbG");
}

pub mod velas {
    pub mod hardfork_pack {
        // 1. difficulty not a hash but a number.
        // 2. transactionRoot, receiptRoot - should calculate, and empty hashes should be setted too
        // 3. nonce is 64bit hash not a number.
        // 4. sha3uncle hash from zero block, not zeros.
        solana_sdk::declare_id!("91nakVjUc5UmNzLioE6K7HhASmb2m1E7hRuLZS4LzUPV");
    }

    pub mod evm_cross_execution {
        solana_sdk::declare_id!("3rkhJCKKR8Szj5v237NzRF3FS2nnyRvaeGF8xAvnVkwf");
    }

    pub mod native_swap_in_evm_history {
        solana_sdk::declare_id!("8h8BTnexqgpfiA8E6Bx8JT97asTPDGBPwhBR98x1Z5cW");
    }
    pub mod evm_new_error_handling {
        solana_sdk::declare_id!("9HscytNCkVfhQYuVbKGdicUzk6zGjRVtwXXbo1b6spRG");
    }
}
lazy_static! {
    /// Map of feature identifiers to user-visible description
    pub static ref FEATURE_NAMES_BEFORE_MAINNET: HashMap<Pubkey, &'static str> = [
        (instructions_sysvar_enabled::id(), "instructions sysvar"),
        (secp256k1_program_enabled::id(), "secp256k1 program"),
        (consistent_recent_blockhashes_sysvar::id(), "consistent recentblockhashes sysvar"),
        (deprecate_rewards_sysvar::id(), "deprecate unused rewards sysvar"),
        (pico_inflation::id(), "pico inflation"),
        (full_inflation::devnet_and_testnet_velas_mainnet::id(), "full inflation on devnet and testnet"),
        (spl_token_v2_multisig_fix::id(), "spl-token multisig fix"),
        (no_overflow_rent_distribution::id(), "no overflow rent distribution"),
        (stake_program_v2::id(), "solana_stake_program v2"),
        (rewrite_stake::id(), "rewrite stake"),
        (filter_stake_delegation_accounts::id(), "filter stake_delegation_accounts #14062"),
        (bpf_loader_upgradeable_program::id(), "upgradeable bpf loader"),
        (stake_program_v3::id(), "solana_stake_program v3"),
        (require_custodian_for_locked_stake_authorize::id(), "require custodian to authorize withdrawer change for locked stake"),
        (spl_token_v2_self_transfer_fix::id(), "spl-token self-transfer fix"),
        (warp_timestamp_again::id(), "warp timestamp again, adjust bounding to 25% fast 80% slow #15204"),
        (check_init_vote_data::id(), "check initialized Vote data"),
        (check_program_owner::id(), "limit programs to operating on accounts owned by itself"),
        /*************** ADD NEW FEATURES HERE ***************/
    ]
        .iter()
        .copied()
        .collect();

    pub static ref FEATURE_NAMES: HashMap<Pubkey, &'static str> = FEATURE_NAMES_BEFORE_MAINNET.iter().map(|(k, v)| (*k, *v)).chain(
        [
            // Solana new features
            (require_stake_for_gossip::id(), "require stakes for propagating crds values through gossip #15561"),
            (cpi_data_cost::id(), "charge the compute budget for data passed via CPI"),
            (upgradeable_close_instruction::id(), "close upgradeable buffer accounts"),
            (demote_sysvar_write_locks::id(), "demote builtins and sysvar write locks to readonly #15497"),
            (sysvar_via_syscall::id(), "provide sysvars via syscalls"),
            (check_duplicates_by_hash::id(), "use transaction message hash for duplicate check"),
            (enforce_aligned_host_addrs::id(), "enforce aligned host addresses"),
            (update_data_on_realloc::id(), "Retain updated data values modified after realloc via CPI"),
            (set_upgrade_authority_via_cpi_enabled::id(), "set upgrade authority instruction via cpi calls for upgradable programs"),
            (keccak256_syscall_enabled::id(), "keccak256 syscall"),
            (stake_program_v4::id(), "solana_stake_program v4"),
            (system_transfer_zero_check::id(), "perform all checks for transfers of 0 lamports"),
            // Velas features
            (velas::hardfork_pack::id(), "EVMblockhashes sysvar history, roothashes calculation. Apply old (reconfigure_native_token, unlock_switch_vote)."),
            (velas::evm_cross_execution::id(), "EVM cross execution."),
            (velas::native_swap_in_evm_history::id(), "Native swap in evm history."),
            (velas::evm_new_error_handling::id(), "EVM new error handling."),
            /*************** ADD NEW FEATURES HERE ***************/
        ]
    ).collect();


    /// Unique identifier of the current software's feature set
    pub static ref ID: Hash = {
        let mut hasher = Hasher::default();
        let mut feature_ids = FEATURE_NAMES.keys().collect::<Vec<_>>();
        feature_ids.sort();
        for feature in feature_ids {
            hasher.hash(feature.as_ref());
        }
        hasher.result()
    };
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FullInflationFeaturePair {
    pub vote_id: Pubkey, // Feature that grants the candidate the ability to enable full inflation
    pub enable_id: Pubkey, // Feature to enable full inflation by the candidate
}

lazy_static! {
    /// Set of feature pairs that once enabled will trigger full inflation
    pub static ref FULL_INFLATION_FEATURE_PAIRS: HashSet<FullInflationFeaturePair> = [
        FullInflationFeaturePair {
            vote_id: full_inflation::mainnet::certusone::vote::id(),
            enable_id: full_inflation::mainnet::certusone::enable::id(),
        },
    ]
        .iter()
        .cloned()
        .collect();
}

/// `FeatureSet` holds the set of currently active/inactive runtime features
#[derive(AbiExample, Debug, Clone)]
pub struct FeatureSet {
    pub active: HashMap<Pubkey, Slot>,
    pub inactive: HashSet<Pubkey>,
}
impl Default for FeatureSet {
    fn default() -> Self {
        // All features disabled
        Self {
            active: HashMap::new(),
            inactive: FEATURE_NAMES.keys().cloned().collect(),
        }
    }
}
impl FeatureSet {
    pub fn is_active(&self, feature_id: &Pubkey) -> bool {
        self.active.contains_key(feature_id)
    }

    pub fn activated_slot(&self, feature_id: &Pubkey) -> Option<Slot> {
        self.active.get(feature_id).copied()
    }

    /// List of enabled features that trigger full inflation
    pub fn full_inflation_features_enabled(&self) -> HashSet<Pubkey> {
        let mut hash_set = FULL_INFLATION_FEATURE_PAIRS
            .iter()
            .filter_map(|pair| {
                if self.is_active(&pair.vote_id) && self.is_active(&pair.enable_id) {
                    Some(pair.enable_id)
                } else {
                    None
                }
            })
            .collect::<HashSet<_>>();

        if self.is_active(&full_inflation::devnet_and_testnet_velas_mainnet::id()) {
            hash_set.insert(full_inflation::devnet_and_testnet_velas_mainnet::id());
        }
        hash_set
    }

    /// All features enabled, useful for testing
    pub fn all_enabled() -> Self {
        Self {
            active: FEATURE_NAMES.keys().cloned().map(|key| (key, 0)).collect(),
            inactive: HashSet::new(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_full_inflation_features_enabled_devnet_and_testnet() {
        let mut feature_set = FeatureSet::default();
        assert!(feature_set.full_inflation_features_enabled().is_empty());
        feature_set
            .active
            .insert(full_inflation::devnet_and_testnet_velas_mainnet::id(), 42);
        assert_eq!(
            feature_set.full_inflation_features_enabled(),
            [full_inflation::devnet_and_testnet_velas_mainnet::id()]
                .iter()
                .cloned()
                .collect()
        );
    }

    #[test]
    fn test_full_inflation_features_enabled() {
        // Normal sequence: vote_id then enable_id
        let mut feature_set = FeatureSet::default();
        assert!(feature_set.full_inflation_features_enabled().is_empty());
        feature_set
            .active
            .insert(full_inflation::mainnet::certusone::vote::id(), 42);
        assert!(feature_set.full_inflation_features_enabled().is_empty());
        feature_set
            .active
            .insert(full_inflation::mainnet::certusone::enable::id(), 42);
        assert_eq!(
            feature_set.full_inflation_features_enabled(),
            [full_inflation::mainnet::certusone::enable::id()]
                .iter()
                .cloned()
                .collect()
        );

        // Backwards sequence: enable_id and then vote_id
        let mut feature_set = FeatureSet::default();
        assert!(feature_set.full_inflation_features_enabled().is_empty());
        feature_set
            .active
            .insert(full_inflation::mainnet::certusone::enable::id(), 42);
        assert!(feature_set.full_inflation_features_enabled().is_empty());
        feature_set
            .active
            .insert(full_inflation::mainnet::certusone::vote::id(), 42);
        assert_eq!(
            feature_set.full_inflation_features_enabled(),
            [full_inflation::mainnet::certusone::enable::id()]
                .iter()
                .cloned()
                .collect()
        );
    }
}
