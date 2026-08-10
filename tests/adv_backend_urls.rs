//! Remote vector: the chain backend endpoint is configurable through `--rpc-url` and
//! `ANZEN_ELECTRUM_URL`, so a user can be pointed at something that is not a Bitcoin node.
//!
//! Public Electrum servers are documented as an availability convenience rather than a trust
//! boundary, so this is purely about robustness: a hostile or wrong endpoint must produce an
//! error, never a panic or a hang.
//!
//! Every address used here is loopback with no listener, so nothing leaves the machine.

use anzen::core::chain::{BitcoinCoreBackend, ElectrumBackend, RpcConfig};
use bitcoin::Network;
use std::time::{Duration, Instant};

fn rpc(url: &str) -> RpcConfig {
    RpcConfig {
        url: url.to_owned(),
        user: "anzen".to_owned(),
        password: "anzen".to_owned(),
    }
}

#[test]
fn hostile_rpc_urls_are_rejected_without_panicking() {
    // Ports on loopback with nothing listening, plus structurally invalid URLs.
    let cases = [
        ("empty", ""),
        ("not a url", "definitely not a url"),
        ("scheme only", "http://"),
        ("no scheme", "127.0.0.1:1"),
        ("closed loopback port", "http://127.0.0.1:1"),
        ("closed high port", "http://127.0.0.1:9"),
        ("unsupported scheme", "ftp://127.0.0.1:1"),
        ("file scheme", "file:///etc/passwd"),
        ("embedded newline", "http://127.0.0.1:1\r\nX-Injected: 1"),
        (
            "very long host",
            "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.invalid:1",
        ),
    ];

    for (label, url) in cases {
        let started = Instant::now();
        let outcome =
            std::panic::catch_unwind(|| BitcoinCoreBackend::connect(&rpc(url), Network::Regtest));
        let elapsed = started.elapsed();
        match &outcome {
            Ok(Ok(_)) => println!("{label:22} -> CONNECTED"),
            Ok(Err(error)) => println!(
                "{label:22} -> rejected in {elapsed:?}: {}",
                format!("{error:#}").lines().next().unwrap_or_default()
            ),
            Err(_) => println!("{label:22} -> PANICKED"),
        }
        assert!(
            outcome.is_ok(),
            "BitcoinCoreBackend::connect panicked on {label}"
        );
        assert!(
            matches!(outcome, Ok(Err(_))),
            "{label} was accepted as a Bitcoin Core endpoint"
        );
        assert!(
            elapsed < Duration::from_secs(60),
            "{label} took {elapsed:?}; a dead endpoint must not hang the CLI"
        );
    }
}

#[test]
fn hostile_electrum_urls_are_rejected_without_panicking() {
    let cases = [
        ("empty list", vec![]),
        ("empty string", vec![""]),
        ("not a url", vec!["definitely not a url"]),
        ("no scheme", vec!["127.0.0.1:1"]),
        ("closed tcp port", vec!["tcp://127.0.0.1:1"]),
        ("closed ssl port", vec!["ssl://127.0.0.1:1"]),
        ("unsupported scheme", vec!["ftp://127.0.0.1:1"]),
        (
            "several dead servers",
            vec![
                "tcp://127.0.0.1:1",
                "tcp://127.0.0.1:9",
                "ssl://127.0.0.1:1",
            ],
        ),
    ];

    for (label, servers) in cases {
        let started = Instant::now();
        let outcome =
            std::panic::catch_unwind(|| ElectrumBackend::connect(Network::Regtest, &servers));
        let elapsed = started.elapsed();
        match &outcome {
            Ok(Ok(_)) => println!("{label:22} -> CONNECTED"),
            Ok(Err(error)) => println!(
                "{label:22} -> rejected in {elapsed:?}: {}",
                format!("{error:#}").lines().next().unwrap_or_default()
            ),
            Err(_) => println!("{label:22} -> PANICKED"),
        }
        assert!(
            outcome.is_ok(),
            "ElectrumBackend::connect panicked on {label}"
        );
        assert!(
            matches!(outcome, Ok(Err(_))),
            "{label} was accepted as an Electrum endpoint"
        );
        assert!(
            elapsed < Duration::from_secs(60),
            "{label} took {elapsed:?}; dead endpoints must not hang the CLI"
        );
    }
}

/// An unsupported network must be refused before any connection is attempted.
#[test]
fn unsupported_networks_are_refused_for_electrum_defaults() {
    for network in [Network::Signet, Network::Testnet] {
        let outcome = std::panic::catch_unwind(|| ElectrumBackend::connect_default(network));
        match &outcome {
            Ok(Ok(_)) => println!("{network:?} -> CONNECTED"),
            Ok(Err(error)) => println!("{network:?} -> refused: {error:#}"),
            Err(_) => println!("{network:?} -> PANICKED"),
        }
        assert!(outcome.is_ok(), "connect_default panicked on {network:?}");
        assert!(matches!(outcome, Ok(Err(_))), "{network:?} was accepted");
    }
}
