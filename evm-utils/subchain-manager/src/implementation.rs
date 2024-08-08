use {
    crate::ChainID,
    solana_client::rpc_config::RpcSendTransactionConfig,
    solana_sdk::signer::{keypair, Signer},
    std::io::{Read, Write},
};

impl super::Config {
    pub fn save(&self) -> Result<(), color_eyre::eyre::Error> {
        let mut file = std::fs::File::create(&self.config_path)?;
        let data = toml::to_string(&self)?;
        file.write_all(data.as_bytes())?;
        Ok(())
    }
    pub fn load(path: &str) -> Result<Self, color_eyre::eyre::Error> {
        let file = std::fs::File::open(path)?;
        let mut buf_reader = std::io::BufReader::new(file);
        let mut contents = String::new();
        buf_reader.read_to_string(&mut contents)?;
        let mut config: Self = toml::from_str(&contents)?;
        config.config_path = path.to_string();
        Ok(config)
    }

    pub fn deploy(
        &self,
        keypair: solana_sdk::signer::keypair::Keypair,
        client: &solana_client::rpc_client::RpcClient,
    ) -> Result<(), color_eyre::eyre::Error> {
        let chain_id = self.chain_id.0;
        let mint: Vec<(_, u64)> = self
            .minting_addresses
            .address
            .iter()
            .cloned()
            .zip(self.minting_addresses.balance.iter().copied())
            .collect();

        // let mint = todo!("{:?}", mint);

        let config = solana_evm_loader_program::instructions::SubchainConfig {
            token_name: self.token_name.clone(),
            network_name: self.network_name.clone(),
            hardfork: match self.hardfork {
                crate::Hardfork::Istanbul => {
                    solana_evm_loader_program::instructions::Hardfork::Istanbul
                }
            },
            mint,
        };
        let owner = keypair.pubkey();
        let ix = solana_evm_loader_program::create_evm_subchain_account(owner, chain_id, config);
        let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
            &[ix],
            Some(&owner),
            &[&keypair],
            client.get_latest_blockhash()?,
        );
        // dry run:
        // println!("{:?}", client.simulate_transaction(&transaction)?);
        client.send_transaction_with_config(
            &transaction,
            RpcSendTransactionConfig {
                skip_preflight: true,
                ..Default::default()
            },
        )?;
        // client.send_and_confirm_transaction(&transaction)?;
        Ok(())
    }
}
