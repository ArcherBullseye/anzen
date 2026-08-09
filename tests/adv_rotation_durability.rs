//! Remote-vector question: what does the wallet destroy locally on the strength of a chain
//! backend's word alone?
//!
//! `activate_phone_rotation` broadcasts the cooperative sweep, then immediately archives the old
//! epoch, overwrites `phone/device.json` with the new mnemonic and overwrites the cloud backup.
//! Nothing waits for the sweep to confirm. A backend only has to *accept* the transaction and
//! return the right txid, which it must do even if it never relays it — and at the fixed
//! 1 sat/vB fee this repo uses, a sweep failing to confirm is an ordinary outcome, not just an
//! adversarial one.

use anyhow::Result;
use anzen::core::{
    chain::{Blockchain, ChainTip},
    storage::{
        CONFIG_FILE, PHONE_DEVICE_FILE, VaultConfig, initialize_vault, load_device, read_json,
        write_json,
    },
    types::VaultUtxo,
};
use anzen::hot_wallet::{HotWallet, HotWalletBackend};
use anzen::{cold_wallet, hot_wallet};
use bitcoin::{
    Address, Amount, BlockHash, Network, OutPoint, Transaction, TxOut, Txid, hashes::Hash as _,
};
use std::str::FromStr;

/// Accepts every broadcast and returns the correct txid, but the transaction never confirms:
/// `scan_vault` keeps reporting the original vault UTXO.
struct NeverConfirmsBackend {
    network: Network,
    utxos: Vec<VaultUtxo>,
}

impl Blockchain for NeverConfirmsBackend {
    fn network(&self) -> Network {
        self.network
    }
    fn backend_description(&self) -> String {
        "backend that accepts but never confirms".to_owned()
    }
    fn chain_tip(&self) -> Result<ChainTip> {
        Ok(ChainTip {
            network: self.network,
            height: 1,
            median_time: 0,
            best_block_hash: BlockHash::all_zeros(),
        })
    }
    fn scan_vault(&self, _config: &VaultConfig) -> Result<Vec<VaultUtxo>> {
        Ok(self.utxos.clone())
    }
    fn broadcast(&self, transaction: &Transaction) -> Result<Txid> {
        // Looks like a success to the caller. Nothing is relayed.
        Ok(transaction.compute_txid())
    }
}

impl HotWalletBackend for NeverConfirmsBackend {
    fn sync_hot_wallet(&self, _wallet: &mut HotWallet) -> Result<()> {
        Ok(())
    }
}

fn contains_recursively(root: &std::path::Path, needle: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if contains_recursively(&path, needle) {
                return true;
            }
        } else if let Ok(text) = std::fs::read_to_string(&path) {
            if text.contains(needle) {
                return true;
            }
        }
    }
    false
}

#[test]
fn rotation_keeps_the_old_phone_key_until_its_sweep_confirms() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let network = Network::Regtest;

    hot_wallet::initialize(&data_dir, network).unwrap();
    cold_wallet::initialize(&data_dir, network).unwrap();
    let mut config = initialize_vault(&data_dir).unwrap();
    config.monthly_limit_sats = 10_000_000;
    config.emergency_access_limit_sats = 0;
    write_json(&data_dir.join(CONFIG_FILE), &config).unwrap();
    cold_wallet::create_cloud_recovery_backup(&data_dir, &config).unwrap();

    let script_pubkey = Address::from_str(&config.vault_address)
        .unwrap()
        .require_network(network)
        .unwrap()
        .script_pubkey();
    let backend = NeverConfirmsBackend {
        network,
        utxos: vec![VaultUtxo {
            outpoint: OutPoint::new(Txid::all_zeros(), 0),
            txout: TxOut {
                value: Amount::from_sat(210_000_000),
                script_pubkey,
            },
            confirmation_height: 1,
        }],
    };

    // The key that currently controls the funded vault.
    let old_phone = load_device(&data_dir, PHONE_DEVICE_FILE).unwrap();
    let old_mnemonic = old_phone.mnemonic.clone();
    let old_vault_address = config.vault_address.clone();

    let package = hot_wallet::create_phone_rotation(&data_dir, &backend).unwrap();
    let approved = cold_wallet::approve_phone_rotation(&data_dir, &package).unwrap();
    let result = hot_wallet::activate_phone_rotation(&data_dir, &backend, &approved).unwrap();
    println!(
        "rotation activated on an unconfirmed sweep: txid={}",
        result.sweep.txid
    );

    let new_config: VaultConfig = read_json(&data_dir.join(CONFIG_FILE)).unwrap();
    let new_phone = load_device(&data_dir, PHONE_DEVICE_FILE).unwrap();
    println!("old vault: {old_vault_address}");
    println!("new vault: {}", new_config.vault_address);
    assert_ne!(
        new_phone.mnemonic, old_mnemonic,
        "the phone key was replaced"
    );

    // The sweep never confirmed, so the funds are still sitting in the OLD vault. Spending them
    // by either fast path needs the OLD phone key. Is any copy of it left on the device?
    let survives = contains_recursively(&data_dir, &old_mnemonic);
    println!("old phone key still present anywhere under the data dir: {survives}");
    assert!(
        survives,
        "the rotation overwrote phone/device.json and the cloud backup with the new key while \
         the sweep was still unconfirmed, so the funds left in the old vault can no longer be \
         reached cooperatively or by phone recovery - only by HWW recovery after 65,535 blocks"
    );
}
