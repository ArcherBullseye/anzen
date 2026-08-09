//! Probe: is `ceremony::validate_batch()` a real security boundary for the monthly calendar?
//!
//! anzen-design.md says each monthly authorization
//!   "uses absolute timestamp `nLockTime` for `00:00 UTC` on the first day of its calendar month"
//! and that "One new monthly-limit authorization becomes available per month."
//!
//! `validate_batch` enforces that with exactly one comparison (src/core/ceremony.rs:605):
//!
//!     if auth_tx.lock_time.to_consensus_u32() != month.unlock_timestamp
//!
//! `month.unlock_timestamp` is a field of the manifest, i.e. it is supplied by the same
//! (untrusted) phone that supplied the PSBT. Nothing binds it to `month.month`, to
//! `manifest.created_at`, to monotonicity, or even to the 500,000,000 timestamp threshold that
//! separates a height lock from a time lock. So the check is self-referential and the HWW will
//! co-sign a batch whose twelve "monthly" authorizations are all spendable immediately.
//!
//! Changing only nLockTime does not change the transaction's vsize, so every fee check in the
//! validator still passes untouched — that is why the tamper survives end to end.

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
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute, hashes::Hash, transaction::Version,
};
use chrono::{TimeZone, Utc};
use std::str::FromStr;

const MONTHLY_LIMIT: u64 = 10_000_000;
const VAULT_BALANCE: u64 = 200_000_000;

struct Fixture {
    _dir: tempfile::TempDir,
    data_dir: std::path::PathBuf,
    batch: std::path::PathBuf,
    #[allow(dead_code)]
    config: VaultConfig,
    policy: VaultPolicy,
    manifest: BatchManifest,
}

fn setup(emergency_limit_sats: u64) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    hot_wallet::initialize(&data_dir, Network::Regtest).unwrap();
    cold_wallet::initialize(&data_dir, Network::Regtest).unwrap();
    let config = initialize_vault_for_network(&data_dir, Network::Regtest).unwrap();

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
            emergency_access_limit_sats: emergency_limit_sats,
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
        config,
        policy,
        manifest,
    }
}

/// Act as a malicious phone: rebuild month `index`'s authorization with `lock_time`, re-sign it
/// with the real phone key, and (optionally) declare the new locktime in the manifest.
fn retarget_authorization_locktime(
    fixture: &mut Fixture,
    index: usize,
    lock_time: absolute::LockTime,
    declare_in_manifest: bool,
) {
    let rollover = read_psbt(&fixture.batch.join(&fixture.manifest.rollover.psbt_file)).unwrap();
    let rollover_tx = rollover.unsigned_tx.clone();
    let month = &fixture.manifest.months[index];
    let hot_script: ScriptBuf = Address::from_str(&month.hot_address)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey();

    let tampered = Transaction {
        version: Version::TWO,
        lock_time,
        input: vec![TxIn {
            previous_output: OutPoint::new(rollover_tx.compute_txid(), index as u32),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(fixture.manifest.monthly_limit_sats),
            script_pubkey: hot_script,
        }],
    };

    let phone = load_device_keys(&fixture.data_dir, PHONE_DEVICE_FILE).unwrap();
    let mut psbt = create_vault_psbt(
        tampered.clone(),
        std::slice::from_ref(&rollover_tx.output[index]),
        &fixture.policy,
    )
    .unwrap();
    sign_vault_psbt(
        &mut psbt,
        &fixture.policy,
        SpendPath::Cooperative,
        &phone.vault_keypair,
    )
    .unwrap();
    let path = fixture
        .batch
        .join(&fixture.manifest.months[index].authorization.psbt_file);
    write_psbt(&path, &psbt).unwrap();

    if declare_in_manifest {
        let month = &mut fixture.manifest.months[index];
        month.unlock_timestamp = lock_time.to_consensus_u32();
        month.authorization.unsigned_txid = tampered.compute_txid().to_string();
        // fee_sats is deliberately left alone: nLockTime does not change the vsize.
    }
    write_json(&fixture.batch.join("manifest.json"), &fixture.manifest).unwrap();
}

/// DEFECT: every "monthly" authorization can carry a *block height* nLockTime of 1, which is
/// already far in the past, and the HWW signs the batch. The design requires an absolute
/// timestamp lock at 00:00 UTC on the first day of the labelled calendar month.
#[test]
fn hww_signs_monthly_authorizations_locked_to_block_height_one() {
    let mut fixture = setup(0);
    assert_eq!(fixture.manifest.chunk_count, 12);
    let honest_fees: Vec<u64> = fixture
        .manifest
        .months
        .iter()
        .map(|month| month.authorization.fee_sats)
        .collect();

    for index in 0..fixture.manifest.months.len() {
        retarget_authorization_locktime(
            &mut fixture,
            index,
            absolute::LockTime::from_height(1).unwrap(),
            true,
        );
    }

    // The calendar labels are untouched; only the enforced locks moved.
    assert_eq!(fixture.manifest.months[0].month, "2026-09");
    assert_eq!(fixture.manifest.months[11].month, "2027-08");
    assert!(
        fixture
            .manifest
            .months
            .iter()
            .zip(&honest_fees)
            .all(|(month, fee)| month.authorization.fee_sats == *fee),
        "fees were not modified, so every fee check still passes"
    );

    let error = cold_wallet::approve_policy(&fixture.data_dir, &fixture.batch)
        .expect_err("height-locked authorizations must be rejected");
    println!("rejected: {error}");
    let message = format!("{error:#}");
    assert!(
        message.contains("approved schedule") || message.contains("violates the approved policy"),
        "rejection must name the schedule, got: {message}"
    );
}

/// DEFECT (same root cause): timestamp locks in the past are accepted too, so the twelve months
/// labelled 2026-09..2027-08 all mature in 1985.
#[test]
fn hww_signs_monthly_authorizations_locked_to_a_1985_timestamp() {
    let mut fixture = setup(0);
    let stale = absolute::LockTime::from_time(500_000_001).unwrap();
    for index in 0..fixture.manifest.months.len() {
        retarget_authorization_locktime(&mut fixture, index, stale, true);
    }
    let error = cold_wallet::approve_policy(&fixture.data_dir, &fixture.batch)
        .expect_err("stale timestamp locks must be rejected");
    println!("rejected: {error}");
    assert!(
        format!("{error:#}").contains("approved schedule"),
        "rejection must name the schedule, got: {error:#}"
    );
}

/// Same root cause, narrower: only the last month is dragged forward to the first month's date,
/// so two "different" months mature at the same instant. "One new monthly-limit authorization
/// becomes available per month" no longer holds.
#[test]
fn hww_signs_two_months_that_mature_at_the_same_instant() {
    let mut fixture = setup(0);
    let first = fixture.manifest.months[0].unlock_timestamp;
    let last_index = fixture.manifest.months.len() - 1;
    retarget_authorization_locktime(
        &mut fixture,
        last_index,
        absolute::LockTime::from_time(first).unwrap(),
        true,
    );
    let error = cold_wallet::approve_policy(&fixture.data_dir, &fixture.batch)
        .expect_err("duplicated month maturities must be rejected");
    println!("rejected: {error}");
    assert!(
        format!("{error:#}").contains("approved schedule"),
        "rejection must name the schedule, got: {error:#}"
    );
}

/// CONTROL: the validator does fire. Moving the PSBT locktime *without* declaring it in the
/// manifest is rejected, which proves the harness exercises the real check and that the defect is
/// specifically the missing binding of `unlock_timestamp` to the calendar month.
#[test]
fn control_hww_rejects_an_undeclared_locktime_change() {
    let mut fixture = setup(0);
    retarget_authorization_locktime(
        &mut fixture,
        0,
        absolute::LockTime::from_height(1).unwrap(),
        false,
    );
    let error = cold_wallet::approve_policy(&fixture.data_dir, &fixture.batch)
        .expect_err("undeclared locktime change must be rejected");
    println!("control rejection: {error}");
}

/// CONTROL: the invariants the assignment calls out as Bitcoin-enforced really are enforced.
/// A revocation that spends a *different* outpoint than its authorization is rejected.
#[test]
fn control_hww_rejects_a_non_conflicting_revocation() {
    let mut fixture = setup(0);
    let rollover = read_psbt(&fixture.batch.join(&fixture.manifest.rollover.psbt_file)).unwrap();
    let rollover_tx = rollover.unsigned_tx.clone();
    let vault_script = fixture.policy.address.script_pubkey();

    // Month 0's revocation is re-pointed at month 1's chunk, so it no longer conflicts with
    // month 0's authorization.
    let month0 = fixture.manifest.months[0].clone();
    let fee = month0.revocation.fee_sats;
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(rollover_tx.compute_txid(), 1),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(month0.chunk_value_sats - fee),
            script_pubkey: vault_script,
        }],
    };
    let phone = load_device_keys(&fixture.data_dir, PHONE_DEVICE_FILE).unwrap();
    let mut psbt = create_vault_psbt(
        tx.clone(),
        std::slice::from_ref(&rollover_tx.output[1]),
        &fixture.policy,
    )
    .unwrap();
    sign_vault_psbt(
        &mut psbt,
        &fixture.policy,
        SpendPath::Cooperative,
        &phone.vault_keypair,
    )
    .unwrap();
    write_psbt(&fixture.batch.join(&month0.revocation.psbt_file), &psbt).unwrap();
    fixture.manifest.months[0].revocation.unsigned_txid = tx.compute_txid().to_string();
    write_json(&fixture.batch.join("manifest.json"), &fixture.manifest).unwrap();

    let error = cold_wallet::approve_policy(&fixture.data_dir, &fixture.batch)
        .expect_err("a revocation that does not conflict must be rejected");
    println!("control rejection: {error}");
}

/// CONTROL: emergency access value conservation and the BIP68 delay are enforced. Inflating the
/// withdrawal amount is rejected.
#[test]
fn control_hww_rejects_an_inflated_emergency_withdrawal() {
    let fixture = setup(50_000_000);
    let emergency = fixture.manifest.emergency_access.clone().unwrap();
    let path = fixture.batch.join(&emergency.withdrawal.psbt_file);
    let mut psbt = read_psbt(&path).unwrap();
    psbt.unsigned_tx.output[0].value = Amount::from_sat(50_000_001);
    write_psbt(&path, &psbt).unwrap();
    let error = cold_wallet::approve_policy(&fixture.data_dir, &fixture.batch)
        .expect_err("an inflated emergency withdrawal must be rejected");
    println!("control rejection: {error}");
}
