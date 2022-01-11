use {
    jsonrpc_core::{MetaIoHandler, Metadata, Result},
    jsonrpc_core_client::{transports::ipc, RpcError},
    jsonrpc_derive::rpc,
    jsonrpc_ipc_server::{RequestContext, ServerBuilder},
    jsonrpc_server_utils::tokio,
    log::*,
    solana_core::validator::{ValidatorExit, ValidatorStartProgress},
    solana_sdk::signature::{read_keypair_file, Keypair, Signer},
    std::{
        net::SocketAddr,
        path::{Path, PathBuf},
        sync::{Arc, RwLock},
        thread::{self, Builder},
        time::{Duration, SystemTime},
    },
};

#[derive(Clone)]
pub struct AdminRpcRequestMetadata {
    pub rpc_addr: Option<SocketAddr>,
    pub start_time: SystemTime,
    pub start_progress: Arc<RwLock<ValidatorStartProgress>>,
    pub validator_exit: Arc<RwLock<ValidatorExit>>,
    pub authorized_voter_keypairs: Arc<RwLock<Vec<Arc<Keypair>>>>,
    pub archive_evm_state: Option<evm_state::Storage>,
}
impl Metadata for AdminRpcRequestMetadata {}

#[rpc]
pub trait AdminRpc {
    type Metadata;

    #[rpc(meta, name = "exit")]
    fn exit(&self, meta: Self::Metadata) -> Result<()>;

    #[rpc(meta, name = "rpcAddress")]
    fn rpc_addr(&self, meta: Self::Metadata) -> Result<Option<SocketAddr>>;

    #[rpc(name = "setLogFilter")]
    fn set_log_filter(&self, filter: String) -> Result<()>;

    #[rpc(meta, name = "startTime")]
    fn start_time(&self, meta: Self::Metadata) -> Result<SystemTime>;

    #[rpc(meta, name = "startProgress")]
    fn start_progress(&self, meta: Self::Metadata) -> Result<ValidatorStartProgress>;

    #[rpc(meta, name = "addAuthorizedVoter")]
    fn add_authorized_voter(&self, meta: Self::Metadata, keypair_file: String) -> Result<()>;

    #[rpc(meta, name = "mergeEvmState")]
    fn merge_evm_state(&self, meta: Self::Metadata, path: String, backup: bool) -> Result<()>;

    #[rpc(meta, name = "removeAllAuthorizedVoters")]
    fn remove_all_authorized_voters(&self, meta: Self::Metadata) -> Result<()>;
}

pub struct AdminRpcImpl;
impl AdminRpc for AdminRpcImpl {
    type Metadata = AdminRpcRequestMetadata;

    fn exit(&self, meta: Self::Metadata) -> Result<()> {
        debug!("exit admin rpc request received");

        thread::spawn(move || {
            // Delay exit signal until this RPC request completes, otherwise the caller of `exit` might
            // receive a confusing error as the validator shuts down before a response is sent back.
            thread::sleep(Duration::from_millis(100));

            warn!("validator exit requested");
            meta.validator_exit.write().unwrap().exit();

            // TODO: Debug why ValidatorExit doesn't always cause the validator to fully exit
            // (rocksdb background processing or some other stuck thread perhaps?).
            //
            // If the process is still alive after five seconds, exit harder
            thread::sleep(Duration::from_secs(5));
            warn!("validator exit timeout");
            std::process::exit(0);
        });
        Ok(())
    }

    fn rpc_addr(&self, meta: Self::Metadata) -> Result<Option<SocketAddr>> {
        debug!("rpc_addr admin rpc request received");
        Ok(meta.rpc_addr)
    }

    fn set_log_filter(&self, filter: String) -> Result<()> {
        debug!("set_log_filter admin rpc request received");
        solana_logger::setup_with(&filter);
        Ok(())
    }

    fn start_time(&self, meta: Self::Metadata) -> Result<SystemTime> {
        debug!("start_time admin rpc request received");
        Ok(meta.start_time)
    }

    fn start_progress(&self, meta: Self::Metadata) -> Result<ValidatorStartProgress> {
        debug!("start_progress admin rpc request received");
        Ok(*meta.start_progress.read().unwrap())
    }

    fn add_authorized_voter(&self, meta: Self::Metadata, keypair_file: String) -> Result<()> {
        debug!("add_authorized_voter request received");

        let authorized_voter = read_keypair_file(keypair_file)
            .map_err(|err| jsonrpc_core::error::Error::invalid_params(format!("{}", err)))?;

        let mut authorized_voter_keypairs = meta.authorized_voter_keypairs.write().unwrap();

        if authorized_voter_keypairs
            .iter()
            .any(|x| x.pubkey() == authorized_voter.pubkey())
        {
            Err(jsonrpc_core::error::Error::invalid_params(
                "Authorized voter already present",
            ))
        } else {
            authorized_voter_keypairs.push(Arc::new(authorized_voter));
            Ok(())
        }
    }

    fn merge_evm_state(&self, meta: Self::Metadata, path: String, backup: bool) -> Result<()> {
        info!("Merging evm state: {}, backup: {}", path, backup);
        let archive_evm_state = if let Some(archive_evm_state) = &meta.archive_evm_state {
            archive_evm_state
        } else {
            error!("Archive storage not found, but merge evm state request received.");
            return Err(jsonrpc_core::Error::invalid_params(
                "Archive storage not found",
            ));
        };

        // Increase variable lifetime, and force drop after merging.
        let tmp_backup_dir;
        let path = if backup {
            let inner_location = archive_evm_state.get_inner_location().map_err(|e| {
                jsonrpc_core::Error::invalid_params(format!(
                    "Cannot get temporary inner location folder {}",
                    e
                ))
            })?;
            tmp_backup_dir = tempfile::tempdir_in(inner_location).map_err(|e| {
                jsonrpc_core::Error::invalid_params(format!(
                    "Cannot create archive storage subfolder {}",
                    e
                ))
            })?;
            let db_dir = tmp_backup_dir.as_ref().join("restored-db");
            evm_state::Storage::restore_from(&path, &db_dir).map_err(|e| {
                jsonrpc_core::Error::invalid_params(format!(
                    "Cannot restore backup for merge database {}",
                    e
                ))
            })?;
            db_dir
        } else {
            PathBuf::from(path)
        };
        let merge_storage = evm_state::Storage::open_persistent(path, false).map_err(|e| {
            jsonrpc_core::Error::invalid_params(format!("Cannot open merge database {}", e))
        })?;

        archive_evm_state
            .merge_from_db(&merge_storage)
            .map_err(|e| {
                jsonrpc_core::Error::invalid_params(format!(
                    "Merge database was not finalized {}",
                    e
                ))
            })
    }

    fn remove_all_authorized_voters(&self, meta: Self::Metadata) -> Result<()> {
        debug!("remove_all_authorized_voters received");
        let mut a = meta.authorized_voter_keypairs.write().unwrap();

        error!("authorized_voter_keypairs pre len: {}", a.len());
        a.clear();
        error!("authorized_voter_keypairs post len: {}", a.len());

        //meta.authorized_voter_keypairs.write().unwrap().clear();
        Ok(())
    }
}

// Start the Admin RPC interface
pub fn run(ledger_path: &Path, metadata: AdminRpcRequestMetadata) {
    let admin_rpc_path = ledger_path.join("admin.rpc");

    let event_loop = tokio::runtime::Builder::new()
        .threaded_scheduler()
        .enable_all()
        .thread_name("sol-adminrpc-el")
        .build()
        .unwrap();

    Builder::new()
        .name("solana-adminrpc".to_string())
        .spawn(move || {
            let mut io = MetaIoHandler::default();
            io.extend_with(AdminRpcImpl.to_delegate());

            let validator_exit = metadata.validator_exit.clone();
            let server = ServerBuilder::with_meta_extractor(io, move |_req: &RequestContext| {
                metadata.clone()
            })
            .event_loop_executor(event_loop.handle().clone())
            .start(&format!("{}", admin_rpc_path.display()));

            match server {
                Err(err) => {
                    warn!("Unable to start admin rpc service: {:?}", err);
                }
                Ok(server) => {
                    let close_handle = server.close_handle();
                    validator_exit
                        .write()
                        .unwrap()
                        .register_exit(Box::new(move || {
                            close_handle.close();
                        }));

                    server.wait();
                }
            }
        })
        .unwrap();
}

// Connect to the Admin RPC interface
pub async fn connect(ledger_path: &Path) -> std::result::Result<gen_client::Client, RpcError> {
    let admin_rpc_path = ledger_path.join("admin.rpc");
    if !admin_rpc_path.exists() {
        Err(RpcError::Client(format!(
            "{} does not exist",
            admin_rpc_path.display()
        )))
    } else {
        ipc::connect::<_, gen_client::Client>(&format!("{}", admin_rpc_path.display())).await
    }
}

pub fn runtime() -> jsonrpc_server_utils::tokio::runtime::Runtime {
    jsonrpc_server_utils::tokio::runtime::Runtime::new().expect("new tokio runtime")
}
