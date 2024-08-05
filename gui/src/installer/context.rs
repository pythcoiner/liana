use std::sync::Arc;
use std::time::Duration;
use std::{path::PathBuf, sync::mpsc};

use crate::hw::HwMessage;
use crate::{
    app::{
        settings::{KeySetting, Settings, WalletSetting},
        wallet::wallet_name,
    },
    bitcoind::{Bitcoind, InternalBitcoindConfig},
    hw::HardwareWalletConfig,
    signer::Signer,
};
use async_hwi::DeviceKind;
use liana::{
    config::Config,
    config::{BitcoinConfig, BitcoindConfig},
    descriptors::LianaDescriptor,
    miniscript::bitcoin,
};

#[derive(Clone)]
pub struct Context {
    pub bitcoin_config: BitcoinConfig,
    pub bitcoind_config: Option<BitcoindConfig>,
    pub descriptor: Option<LianaDescriptor>,
    pub keys: Vec<KeySetting>,
    pub hws: Vec<(DeviceKind, bitcoin::bip32::Fingerprint, Option<[u8; 32]>)>,
    pub data_dir: PathBuf,
    pub hw_is_used: bool,
    // In case a user entered a mnemonic,
    // we dont want to override the generated signer with it.
    pub recovered_signer: Option<Arc<Signer>>,
    pub bitcoind_is_external: bool,
    pub internal_bitcoind_config: Option<InternalBitcoindConfig>,
    pub internal_bitcoind: Option<Bitcoind>,
    pub hw_sender: mpsc::Sender<HwMessage>,
}

impl Context {
    pub fn new(
        network: bitcoin::Network,
        data_dir: PathBuf,
        hw_sender: mpsc::Sender<HwMessage>,
    ) -> Self {
        Self {
            bitcoin_config: BitcoinConfig {
                network,
                poll_interval_secs: Duration::from_secs(30),
            },
            hws: Vec::new(),
            keys: Vec::new(),
            bitcoind_config: None,
            descriptor: None,
            data_dir,
            hw_is_used: false,
            recovered_signer: None,
            bitcoind_is_external: true,
            internal_bitcoind_config: None,
            internal_bitcoind: None,
            hw_sender,
        }
    }

    pub fn extract_gui_settings(&self) -> Settings {
        let hardware_wallets = self
            .hws
            .iter()
            .filter_map(|(kind, fingerprint, token)| {
                token
                    .as_ref()
                    .map(|token| HardwareWalletConfig::new(kind, *fingerprint, token))
            })
            .collect();
        let descriptor = self
            .descriptor
            .as_ref()
            .expect("Must be a descriptor at this point");
        Settings {
            wallets: vec![WalletSetting {
                name: wallet_name(descriptor),
                descriptor_checksum: descriptor
                    .to_string()
                    .split_once('#')
                    .map(|(_, checksum)| checksum)
                    .unwrap()
                    .to_string(),
                keys: self.keys.clone(),
                hardware_wallets,
            }],
        }
    }

    pub fn extract_daemon_config(&self) -> Config {
        Config {
            #[cfg(unix)]
            daemon: false,
            log_level: log::LevelFilter::Info,
            main_descriptor: self.descriptor.clone().unwrap(),
            data_dir: Some(self.data_dir.clone()),
            bitcoin_config: self.bitcoin_config.clone(),
            bitcoind_config: self.bitcoind_config.clone(),
        }
    }
}
