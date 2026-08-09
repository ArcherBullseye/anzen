//! Probe: does `VaultPolicy::leaf()` disambiguate the two depth-2 recovery leaves safely?
//!
//! `leaf()` (src/core/policy.rs) picks between PhoneRecovery and HwwRecovery by scanning each
//! depth-2 leaf script for the *encoded pushdata bytes* of that path's CSV delay:
//!
//!     phone delay 61200 -> pushdata bytes 03 10 ef 00
//!     hww   delay 65535 -> pushdata bytes 03 ff ff 00
//!
//! Both recovery scripts also embed a 32-byte x-only pubkey. If a key contains the *other*
//! path's delay pattern, the byte-window search can select the wrong leaf. Only public keys are
//! needed to demonstrate this; `leaf()` never touches private keys.

use anzen::core::{
    keys::DeviceKeys,
    policy::{SpendPath, VaultPolicy},
};
use bitcoin::{
    opcodes::all::{OP_CHECKSIG, OP_CSV, OP_VERIFY},
    script::Builder,
    secp256k1::{Secp256k1, XOnlyPublicKey},
};

fn delay_pattern(delay: u16) -> Vec<u8> {
    Builder::new()
        .push_int(i64::from(delay))
        .into_script()
        .as_bytes()
        .to_vec()
}

fn recovery_script(key: XOnlyPublicKey, delay: u16) -> Vec<u8> {
    Builder::new()
        .push_int(i64::from(delay))
        .push_opcode(OP_CSV)
        .push_opcode(OP_VERIFY)
        .push_x_only_key(&key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
        .as_bytes()
        .to_vec()
}

/// Find a valid x-only pubkey whose 32-byte serialization contains `pattern` at `offset`.
fn key_containing(pattern: &[u8], offset: usize) -> Option<XOnlyPublicKey> {
    let mut bytes = [0_u8; 32];
    for counter in 0_u64..2_000_000 {
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (counter.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> ((i % 8) * 8)) as u8
                ^ (i as u8).wrapping_mul(31);
        }
        bytes[offset..offset + pattern.len()].copy_from_slice(pattern);
        if let Ok(key) = XOnlyPublicKey::from_slice(&bytes) {
            return Some(key);
        }
    }
    None
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn honest_key() -> XOnlyPublicKey {
    DeviceKeys::generate(&Secp256k1::new())
        .unwrap()
        .vault_pubkey
}

/// A phone key containing the HWW delay pattern hijacks `leaf(HwwRecovery)`.
#[test]
fn phone_key_containing_the_hww_delay_pattern_hijacks_the_hww_recovery_leaf() {
    let phone = key_containing(&delay_pattern(65_535), 10).expect("no colliding phone key");
    let hww = honest_key();
    println!("phone x-only key: {}", hex(&phone.serialize()));
    println!("hww   x-only key: {}", hex(&hww.serialize()));

    let policy = VaultPolicy::new(phone, hww).unwrap();
    let hww_leaf = policy.leaf(SpendPath::HwwRecovery).unwrap();

    let expected_hww = recovery_script(hww, 65_535);
    let phone_script = recovery_script(phone, 61_200);

    println!("returned  : {}", hex(hww_leaf.script.as_bytes()));
    println!("expected  : {}", hex(&expected_hww));
    println!(
        "is actually the phone leaf: {}",
        hww_leaf.script.as_bytes() == phone_script.as_slice()
    );

    assert_eq!(
        hww_leaf.script.as_bytes(),
        expected_hww.as_slice(),
        "leaf(HwwRecovery) returned the wrong script"
    );
}

/// Downstream impact: the HWW cannot sign its own unilateral recovery path.
#[test]
fn hww_cannot_sign_its_recovery_path_when_the_phone_key_collides() {
    use anzen::core::transactions::{create_vault_psbt, sign_vault_psbt};
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
        transaction::Version,
    };

    let secp = Secp256k1::new();
    let hww_keys = DeviceKeys::generate(&secp).unwrap();
    let phone = key_containing(&delay_pattern(65_535), 10).expect("no colliding phone key");
    let policy = VaultPolicy::new(phone, hww_keys.vault_pubkey).unwrap();

    let prevout = TxOut {
        value: Amount::from_sat(20_000_000),
        script_pubkey: policy.address.script_pubkey(),
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence(65_535),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(19_999_800),
            script_pubkey: ScriptBuf::new_p2tr(&secp, hww_keys.vault_pubkey, None),
        }],
    };
    let mut psbt = create_vault_psbt(tx, &[prevout], &policy).unwrap();

    let result = sign_vault_psbt(
        &mut psbt,
        &policy,
        SpendPath::HwwRecovery,
        &hww_keys.vault_keypair,
    );
    match &result {
        Ok(()) => println!("HWW recovery signing succeeded"),
        Err(error) => println!("HWW recovery signing FAILED: {error}"),
    }
    assert!(
        result.is_ok(),
        "the HWW could not sign its own recovery path"
    );
}

/// Control: the reverse direction is saved by iteration order, so the bug is one-directional.
#[test]
fn hww_key_containing_the_phone_delay_pattern_is_harmless() {
    let phone = honest_key();
    let hww = key_containing(&delay_pattern(61_200), 10).expect("no colliding hww key");
    let policy = VaultPolicy::new(phone, hww).unwrap();

    assert_eq!(
        policy
            .leaf(SpendPath::PhoneRecovery)
            .unwrap()
            .script
            .as_bytes(),
        recovery_script(phone, 61_200).as_slice(),
        "leaf(PhoneRecovery) returned the wrong script"
    );
    assert_eq!(
        policy
            .leaf(SpendPath::HwwRecovery)
            .unwrap()
            .script
            .as_bytes(),
        recovery_script(hww, 65_535).as_slice(),
        "leaf(HwwRecovery) returned the wrong script"
    );
}
