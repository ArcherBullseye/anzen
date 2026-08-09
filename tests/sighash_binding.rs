//! A vault co-signature must commit to the transaction's outputs.
//!
//! `sign_vault_psbt` derives the sighash via `psbt.sighash_msg()`, which honours the
//! *declared* `sighash_type` on the PSBT input. That field arrives with the PSBT, so a
//! malicious proposer can ask for SIGHASH_NONE — under which the signature commits to no
//! outputs at all — and then redirect the money after the hardware wallet has co-signed.
//!
//! The signature was stored with a hardcoded `TapSighashType::Default` label, so the
//! "non-default sighash" guard in `verify_vault_psbt_signature` inspected a constant and
//! never fired.

use anzen::core::{
    keys::DeviceKeys,
    policy::{SpendPath, VaultPolicy},
    transactions::{create_vault_psbt, sign_vault_psbt},
};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
    key::Secp256k1, psbt::PsbtSighashType, sighash::TapSighashType, transaction::Version,
};

fn vault_spend(policy: &VaultPolicy, destination: ScriptBuf) -> (Transaction, TxOut) {
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
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(19_999_800),
            script_pubkey: destination,
        }],
    };
    (tx, prevout)
}

/// Every non-default Taproot sighash must be refused outright at signing time.
#[test]
fn signing_refuses_a_psbt_that_requests_a_non_default_sighash() {
    let secp = Secp256k1::new();
    let phone = DeviceKeys::generate(&secp).unwrap();
    let hww = DeviceKeys::generate(&secp).unwrap();
    let policy = VaultPolicy::new(phone.vault_pubkey, hww.vault_pubkey).unwrap();
    let honest_destination = ScriptBuf::new_p2tr(&secp, phone.vault_pubkey, None);

    for hostile in [
        TapSighashType::None,
        TapSighashType::Single,
        TapSighashType::All,
        TapSighashType::NonePlusAnyoneCanPay,
        TapSighashType::SinglePlusAnyoneCanPay,
        TapSighashType::AllPlusAnyoneCanPay,
    ] {
        let (tx, prevout) = vault_spend(&policy, honest_destination.clone());
        let mut psbt = create_vault_psbt(tx, &[prevout], &policy).unwrap();

        // The proposer rewrites the requested sighash before handing the PSBT over.
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(hostile));

        let result = sign_vault_psbt(
            &mut psbt,
            &policy,
            SpendPath::Cooperative,
            &hww.vault_keypair,
        );
        match &result {
            Ok(()) => println!("{hostile:?}: SIGNED (vault co-signature does not bind outputs)"),
            Err(error) => println!("{hostile:?}: refused - {error}"),
        }
        assert!(
            result.is_err(),
            "the hardware wallet signed a {hostile:?} digest; that signature does not commit \
             to the outputs and lets the proposer redirect the funds"
        );
    }
}

/// The honest path must keep working: an absent or explicitly-Default sighash still signs.
#[test]
fn signing_still_accepts_the_default_sighash() {
    let secp = Secp256k1::new();
    let phone = DeviceKeys::generate(&secp).unwrap();
    let hww = DeviceKeys::generate(&secp).unwrap();
    let policy = VaultPolicy::new(phone.vault_pubkey, hww.vault_pubkey).unwrap();
    let destination = ScriptBuf::new_p2tr(&secp, phone.vault_pubkey, None);

    // Explicitly Default, as create_vault_psbt sets it.
    let (tx, prevout) = vault_spend(&policy, destination.clone());
    let mut psbt = create_vault_psbt(tx, &[prevout], &policy).unwrap();
    sign_vault_psbt(
        &mut psbt,
        &policy,
        SpendPath::Cooperative,
        &hww.vault_keypair,
    )
    .expect("an explicitly-Default PSBT must still sign");

    // Absent: BIP341 treats a missing sighash type as Default.
    let (tx, prevout) = vault_spend(&policy, destination);
    let mut psbt = create_vault_psbt(tx, &[prevout], &policy).unwrap();
    psbt.inputs[0].sighash_type = None;
    sign_vault_psbt(
        &mut psbt,
        &policy,
        SpendPath::Cooperative,
        &hww.vault_keypair,
    )
    .expect("an absent sighash type means Default and must still sign");
}
