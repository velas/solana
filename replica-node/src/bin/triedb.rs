//! The main AccountsDb replication node responsible for replicating
//! AccountsDb information from peer a validator or another replica-node.

#![allow(clippy::integer_arithmetic)]

use std::net::SocketAddr;

use solana_replica_node::triedb_replica_service;

use {
    clap::{crate_description, crate_name, App, AppSettings, Arg},
    std::{env, path::PathBuf},
};

use evm_state::Storage;

pub fn main() -> Result<(), Box<(dyn std::error::Error + 'static)>> {

    let matches = App::new(crate_name!())
        .about(crate_description!())
        .version(solana_version::version!())
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::InferSubcommands)
        .arg(
            Arg::with_name("evm_state")
                .short("e")
                .long("evm-state")
                .value_name("DIR")
                .takes_value(true)
                .required(true)
                .help("Use DIR as ledger location"),
        )
        .arg(
            Arg::with_name("bind_address")
                .long("bind-address")
                .value_name("HOST:PORT")
                .takes_value(true)
                .validator(solana_net_utils::is_host_port)
                .required(true)
                .help("IP:PORT address to bind the state gRPC server"),
        )
        .get_matches();

    let _ = env_logger::Builder::new().parse_filters("info").try_init();

    let evm_state = PathBuf::from(matches.value_of("evm_state").unwrap());
    log::info!("{:?}", evm_state);

    let socket_addr = matches.value_of("bind_address").unwrap();

    let state_rpc_bind_address: SocketAddr = socket_addr.parse()?;
    // let gc_enabled = true;
    let gc_enabled = false;

    let storage = Storage::open_persistent(evm_state, gc_enabled)?;
    triedb_replica_service::start_and_join(state_rpc_bind_address, storage)?;
    Ok(())
}
