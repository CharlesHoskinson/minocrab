//! The disclosure report, valued: what a real run of a real circuit made
//! public, resolved to the values it took (M9 phase 6).
//!
//! The generated set-equality tests beside each circuit check the LABELS,
//! statically and cheaply. This is the other half — the v3 twin of v2's
//! `simulate_compiled` report — and it needs a `ProofPreimage`, so it lives
//! here, on the vault harness that already builds one.
//!
//! What it pins is the whole reporting path at once: that a v3 `Disclosure3`
//! carries an `Identifier` the simulator's memory can be keyed by (before
//! phase 6 it carried `index: 0`, and every value in a v3 report would have
//! read `<not computed>`); that a `Bytes<32>` disclosed under one label
//! reports BOTH limbs under that one label; and that the values are the
//! preimage's own.

use midnight_transient_crypto::proofs::ProofPreimage;
use minocrab::v3::Compiled3;
use minocrab_contracts::erc20_vault;
use minocrab_sim::v3::simulate_compiled;

mod support;
mod vault;

use vault::model::*;

/// The golden: `startDeposit`'s disclosure report, line by line
/// (`label | kind | values`).
///
/// Regenerate with `--ignored --nocapture print_start_deposit_disclosure_report`.
const START_DEPOSIT_REPORT: &str = "\
depositor identity commitment | disclosed | -, 0f9c39975e1f14849c53385ebc9e0298aef16bb918faa6186e06691a2c7e28
impact public input | statement | 01
the caller's EVM account nonce | disclosed | 11
the caller-chosen request index | disclosed | bc9a78563412
the deposited ERC20 | disclosed | 65726332302d746f6b656e2d6164647265737321
the deposited amount | disclosed | 40420f
the request's EIP-1559 fee envelope | disclosed | 00902f5009
the request's EIP-1559 fee envelope | disclosed | 00943577
the request's EIP-1559 fee envelope | disclosed | 905f01
the request's ownership commitment | disclosed | -, 3ccff5f8d992d4111463daaf9853d87eaf1d2ee838157f016a56692a715993";

fn report_lines(compiled: &Compiled3, pi: &ProofPreimage) -> Vec<String> {
    let (_run, report) = simulate_compiled(compiled, pi).expect("the circuit accepts");
    report
        .disclosures
        .iter()
        .map(|d| format!("{} | {} | {}", d.label, d.kind, d.values.join(", ")))
        .collect()
}

/// Every disclosure `startDeposit` makes, with this run's values.
#[test]
fn the_start_deposit_disclosure_report_is_valued() {
    let compiled = erc20_vault::Vault::start_deposit();
    let pi = StartScenario::deposit().preimage();
    let lines = report_lines(&compiled, &pi);

    // Nothing resolves to `<not computed>`: every record points at a value
    // the run actually produced — the Identifier fix, in one assertion.
    assert!(
        !lines.iter().any(|l| l.contains("<not computed>")),
        "a disclosure did not resolve:\n{}",
        lines.join("\n")
    );

    // One record per LOGICAL value, however many wires it has: the two
    // commitments — the depositor's identity and the request's ownership —
    // report their two limbs each on one line, and the deposited ERC20, the
    // caller-chosen request index, the deposited amount and the caller's EVM
    // account nonce one each. The gas params are three records under ONE
    // label (gas limit, maxFeePerGas, maxPriorityFeePerGas, in that order),
    // so nine lines for seven labels. Under M44's flush pattern
    // `startDeposit` only files the request, so the cross-contract call's
    // own disclosures — the entry-point hash and the communications
    // commitment — are `sendDeposit`'s, not this circuit's.
    let disclosed: Vec<&String> = lines.iter().filter(|l| l.contains("| disclosed |")).collect();
    assert_eq!(disclosed.len(), 9, "{}", lines.join("\n"));

    let golden: Vec<String> = START_DEPOSIT_REPORT.lines().map(str::to_string).collect();
    let summary = summarize(&lines);
    assert_eq!(summary, golden, "\nBUILT:\n{}\n", summary.join("\n"));
}

/// The report is long (one `statement` line per Impact input); the golden
/// keeps every `disclosed` line and one representative `statement` line.
fn summarize(lines: &[String]) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    let mut seen_statement = false;
    for line in lines {
        if line.contains("| statement |") {
            if seen_statement {
                continue;
            }
            seen_statement = true;
        }
        kept.push(line.clone());
    }
    kept.sort();
    kept
}

#[test]
#[ignore]
fn print_start_deposit_disclosure_report() {
    let compiled = erc20_vault::Vault::start_deposit();
    let pi = StartScenario::deposit().preimage();
    for line in summarize(&report_lines(&compiled, &pi)) {
        println!("{line}");
    }
}
