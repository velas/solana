use {
    crossbeam_channel::{Receiver, RecvTimeoutError, Sender},
    evm_state::Block,
    solana_ledger::blockstore::Blockstore,
    solana_program_runtime::evm_executor_context::Chain,
    std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub type EvmRecorderReceiver = Receiver<(Chain, Block)>;
pub type EvmRecorderSender = Sender<(Chain, Block)>;

pub struct EvmRecorderService {
    thread_hdl: JoinHandle<()>,
}

impl EvmRecorderService {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        evm_recorder_receiver: EvmRecorderReceiver,
        blockstore: Arc<Blockstore>,
        exit: &Arc<AtomicBool>,
    ) -> Self {
        let exit = exit.clone();
        let thread_hdl = Builder::new()
            .name("evm-block-writer".to_string())
            .spawn(move || loop {
                if exit.load(Ordering::Relaxed) {
                    break;
                }
                if let Err(RecvTimeoutError::Disconnected) =
                    Self::write_evm_record(&evm_recorder_receiver, &blockstore)
                {
                    break;
                }
            })
            .unwrap();
        Self { thread_hdl }
    }

    fn write_evm_record(
        evm_records_receiver: &EvmRecorderReceiver,
        blockstore: &Arc<Blockstore>,
    ) -> Result<(), RecvTimeoutError> {
        let (chain, block) = evm_records_receiver.recv_timeout(Duration::from_secs(1))?;
        let block_header = block.header;
        debug!("Writing evm block num = {}", block_header.block_number);
        blockstore
            .write_evm_block_header(&chain, &block_header)
            .expect("Expected database write to succed");
        for (hash, tx) in block.transactions {
            blockstore
                .write_evm_transaction(
                    &chain, 
                    block_header.block_number,
                    block_header.native_chain_slot,
                    hash,
                    tx,
                )
                .expect("Expected database write to succed");
        }
        Ok(())
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}
