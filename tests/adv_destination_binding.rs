//! Does the hardware wallet independently validate where the money goes?
//!
//! `anzen-design.md:187` states the HWW "independently validates the source outpoint, exact
//! amount, destination, delay, change, fees, and conflicting cancellation before signing".
//!
//! In `validate_batch` the destination check is
//!
//!     auth_tx.output[0].script_pubkey != hot_script
//!
//! where `hot_script` is derived from `month.hot_address` — a field of the manifest the phone
//! supplies. The config does carry `phone_hot_external_descriptor`, and the project already
//! pins addresses to the phone's derived sequence elsewhere
//! (`validate_rotation_hot_addresses`), so the question is whether the annual ceremony does the
//! same or takes the phone's word.
//!
//! An attacker-chosen P2TR destination keeps every transaction the same size, so all the fee and
//! value checks continue to pass untouched.

use anzen::core::{
    ceremony::{BatchManifest, PolicyLimits, build_policy_proposal, read_psbt, write_psbt},
    policy::{SpendPath, VaultPolicy},
    storage::{
        PHONE_DEVICE_FILE, VaultConfig, initialize_vault_for_network, load_device_keys, write_json,
    },
    transactions::{create_vault_psbt, sign_vault_psbt},
    types::VaultUtxo,
};
use anzen::{cold_wallet, hot_wallet, hot_wallet::HotWallet};
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness,
    hashes::Hash,
    key::{Keypair, Secp256k1},
    secp256k1::XOnlyPublicKey,
};
use chrono::{TimeZone, Utc};
use std::{path::PathBuf, str::FromStr};

const VAULT_BALANCE: u64 = 200_000_000;
const MONTHLY_LIMIT: u64 = 10_000_000;
const EMERGENCY_LIMIT: u64 = 50_000_000;

struct Fixture {
    _dir: tempfile::TempDir,
    data_dir: PathBuf,
    batch: PathBuf,
    policy: VaultPolicy,
    manifest: BatchManifest,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    hot_wallet::initialize(&data_dir, Network::Regtest).unwrap();
    cold_wallet::initialize(&data_dir, Network::Regtest).unwrap();
    let config: VaultConfig = initialize_vault_for_network(&data_dir, Network::Regtest).unwrap();

    let vault_script = Address::from_str(&config.vault_address)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey();
    let utxo = VaultUtxo {
        outpoint: OutPoint::new(Txid::all_zeros(), 0),
        txout: TxOut {
            value: Amount::from_sat(VAULT_BALANCE),
            script_pubkey: vault_script,
        },
        confirmation_height: 1,
    };
    let batch = data_dir.join("batch");
    let phone = load_device_keys(&data_dir, PHONE_DEVICE_FILE).unwrap();
    let mut hot = HotWallet::open_or_create(&data_dir).unwrap();
    let manifest = build_policy_proposal(
        &config,
        &[utxo],
        Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
        PolicyLimits {
            monthly_limit_sats: MONTHLY_LIMIT,
            emergency_access_limit_sats: EMERGENCY_LIMIT,
        },
        &batch,
        &phone,
        &mut hot,
    )
    .unwrap();
    let policy =
        VaultPolicy::from_descriptor_for_network(&config.vault_descriptor, Network::Regtest)
            .unwrap();
    Fixture {
        _dir: dir,
        data_dir,
        batch,
        policy,
        manifest,
    }
}

/// A P2TR address the honest owner does not control.
fn attacker_address(secp: &Secp256k1<bitcoin::secp256k1::All>) -> (Address, ScriptBuf) {
    let keypair = Keypair::new(secp, &mut bitcoin::key::rand::thread_rng());
    let (pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
    let script = ScriptBuf::new_p2tr(secp, pubkey, None);
    let address = Address::from_script(&script, Network::Regtest).unwrap();
    (address, script)
}

/// Rebuild one transaction with a new output script, re-sign it with the genuine phone key, and
/// write it back over the batch artifact.
fn repoint(
    fixture: &Fixture,
    psbt_file: &str,
    prevout: &TxOut,
    outpoint: OutPoint,
    destination: ScriptBuf,
) -> Txid {
    let original = read_psbt(&fixture.batch.join(psbt_file)).unwrap();
    let mut tx: Transaction = original.unsigned_tx.clone();
    tx.output[0].script_pubkey = destination;
    let _ = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: tx.input[0].sequence,
        witness: Witness::new(),
    };
    let mut psbt = create_vault_psbt(tx.clone(), std::slice::from_ref(prevout), &fixture.policy)
        .expect("rebuild psbt");
    let phone = load_device_keys(&fixture.data_dir, PHONE_DEVICE_FILE).unwrap();
    sign_vault_psbt(
        &mut psbt,
        &fixture.policy,
        SpendPath::Cooperative,
        &phone.vault_keypair,
    )
    .unwrap();
    write_psbt(&fixture.batch.join(psbt_file), &psbt).unwrap();
    tx.compute_txid()
}

/// Monthly allowances redirected to an address the owner does not control must be refused.
#[test]
fn hww_refuses_monthly_allowances_paid_to_a_foreign_address() {
    let secp = Secp256k1::new();
    let mut fixture = setup();
    let rollover = read_psbt(&fixture.batch.join(&fixture.manifest.rollover.psbt_file)).unwrap();
    let rollover_tx = rollover.unsigned_tx.clone();
    let honest_fees: Vec<u64> = fixture
        .manifest
        .months
        .iter()
        .map(|m| m.authorization.fee_sats)
        .collect();

    for index in 0..fixture.manifest.months.len() {
        let (address, script) = attacker_address(&secp);
        let file = fixture.manifest.months[index]
            .authorization
            .psbt_file
            .clone();
        let txid = repoint(
            &fixture,
            &file,
            &rollover_tx.output[index],
            OutPoint::new(rollover_tx.compute_txid(), index as u32),
            script,
        );
        let month = &mut fixture.manifest.months[index];
        month.hot_address = address.to_string();
        month.authorization.unsigned_txid = txid.to_string();
    }
    write_json(&fixture.batch.join("manifest.json"), &fixture.manifest).unwrap();

    assert!(
        fixture
            .manifest
            .months
            .iter()
            .zip(&honest_fees)
            .all(|(m, fee)| m.authorization.fee_sats == *fee),
        "a P2TR destination keeps the size identical, so no fee check moved"
    );

    let approved = cold_wallet::approve_policy(&fixture.data_dir, &fixture.batch);
    match &approved {
        Ok(_) => println!(
            "HWW APPROVED: all 12 monthly allowances ({} sats) redirected to foreign addresses",
            MONTHLY_LIMIT * 12
        ),
        Err(error) => println!("refused: {error}"),
    }
    let error = approved.expect_err("foreign monthly destinations must be refused");
    assert!(
        format!("{error:#}").contains("not the phone's hot address"),
        "rejection must name the destination, got: {error:#}"
    );
}

/// The emergency withdrawal, which is not bounded by the monthly limit, must be refused too.
#[test]
fn hww_refuses_an_emergency_withdrawal_paid_to_a_foreign_address() {
    let secp = Secp256k1::new();
    let mut fixture = setup();
    let emergency = fixture.manifest.emergency_access.clone().unwrap();
    let trigger = read_psbt(&fixture.batch.join(&emergency.trigger.psbt_file)).unwrap();
    let staging = trigger.unsigned_tx.output[0].clone();
    let staging_outpoint = OutPoint::new(trigger.unsigned_tx.compute_txid(), 0);

    let (address, script) = attacker_address(&secp);
    let txid = repoint(
        &fixture,
        &emergency.withdrawal.psbt_file,
        &staging,
        staging_outpoint,
        script,
    );

    let slot = fixture.manifest.emergency_access.as_mut().unwrap();
    slot.hot_address = address.to_string();
    slot.withdrawal.unsigned_txid = txid.to_string();
    write_json(&fixture.batch.join("manifest.json"), &fixture.manifest).unwrap();

    let approved = cold_wallet::approve_policy(&fixture.data_dir, &fixture.batch);
    match &approved {
        Ok(_) => println!(
            "HWW APPROVED: the {EMERGENCY_LIMIT}-sat emergency withdrawal now pays {address}"
        ),
        Err(error) => println!("refused: {error}"),
    }
    let error = approved.expect_err("a foreign emergency destination must be refused");
    assert!(
        format!("{error:#}").contains("not the phone's hot address"),
        "rejection must name the destination, got: {error:#}"
    );
}

/// The check is feasible: the config already carries the phone's hot descriptor, and deriving
/// an address from it needs only miniscript, which `core` already depends on. So a foreign
/// address is distinguishable from one of the phone's own without `cold_wallet` ever reaching
/// into `hot_wallet`.
#[test]
fn the_phone_hot_descriptor_in_the_config_can_identify_its_own_addresses() {
    use miniscript::{Descriptor, descriptor::DescriptorPublicKey};

    let secp = Secp256k1::new();
    let fixture = setup();
    let config: VaultConfig = anzen::core::storage::load_config(&fixture.data_dir).unwrap();
    let descriptor =
        Descriptor::<DescriptorPublicKey>::from_str(&config.phone_hot_external_descriptor)
            .expect("the config's hot descriptor parses with miniscript alone");

    let derived: Vec<String> = (0..20_u32)
        .map(|index| {
            descriptor
                .at_derivation_index(index)
                .unwrap()
                .address(Network::Regtest)
                .unwrap()
                .to_string()
        })
        .collect();

    // Every address the ceremony actually used is one of the phone's own.
    for month in &fixture.manifest.months {
        assert!(
            derived.contains(&month.hot_address),
            "month {} used {} which is not derivable from the phone's hot descriptor",
            month.month,
            month.hot_address
        );
    }
    let emergency = fixture.manifest.emergency_access.clone().unwrap();
    assert!(derived.contains(&emergency.hot_address));

    // An attacker's address is not.
    let (foreign, _) = attacker_address(&secp);
    assert!(
        !derived.contains(&foreign.to_string()),
        "a foreign address must not be derivable from the phone's descriptor"
    );
    println!(
        "all {} ceremony destinations derive from config.phone_hot_external_descriptor; \
         a foreign address does not",
        fixture.manifest.months.len() + 1
    );
}

/// Control: the untouched batch is approved, so the harness exercises the real path.
#[test]
fn control_the_honest_batch_is_approved() {
    let fixture = setup();
    cold_wallet::approve_policy(&fixture.data_dir, &fixture.batch)
        .expect("the honest batch must still be approved");
}
