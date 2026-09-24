//! M43 rung D — THE POSTING BENCHMARK: what it costs to post one signer
//! event on chain, under OUR artifact and under compactc's, for the same
//! call.
//!
//! `#[ignore]`d, `--release`, and it needs the KZG params on disk:
//!
//! ```console
//! cargo test --release -p minocrab-contracts --test signet_posting -- --ignored posting_benchmark --nocapture
//! ```
//!
//! `crates/minocrab-bench` prices the PROOF (keygen, prove, verify, RSS);
//! this gate prices the TRANSACTION, the way a chain does. Per circuit ×
//! side it runs the whole posting path in one subprocess (so peak RSS is
//! the cell's own): keygen from that side's IR → deploy the singleton under
//! that side's verifier key → build the same call the other gates build →
//! `Transaction::prove` in process → `seal` → `well_formed` with proofs
//! verified in `Real` mode → `apply`; and it reads off the ledger what the
//! ledger would charge: `Transaction::cost` (the `SyntheticCost` the fee
//! model normalises) and `Transaction::fees` under `INITIAL_PARAMETERS`, in
//! SPECKS. The sides:
//!
//! - `minocrab`: `signet_contract::SignetContract::*().ir`, the artifact
//!   `crates/signet-artifacts` ships;
//! - `compactc`: the corpus `.zkir` compactc 0.34.0 wrote for the same
//!   source (midnight-integration PR #127, `e9350c4`), keygen'd here with
//!   the same `midnight-zkir-v3`.
//!
//! What is EXPECTED equal, and why: the proof (same proof system, same
//! `k`-independent proof size), the verifier key size (1353 bytes both,
//! the fixed-column count does not depend on `k`), the transcript (the
//! call-compatibility gates prove both artifacts accept the identical
//! preimage), hence the cost model's inputs, hence the fee. What is
//! expected to differ: `k`, rows, prover-key bytes, keygen and prove time,
//! peak RSS — the prover's side of the ledger. The table says which held.
//!
//! The parent test spawns `--measure`-style children through the test
//! binary itself (`MINOCRAB_POSTING_CELL=<side>:<circuit>` selects the cell
//! for `measure_one_cell`), collects one JSON line each, and writes
//! `target/bench/posting.{jsonl,md}`.

use std::time::Instant;

use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use midnight_base_crypto::fab::AlignedValue;
use midnight_base_crypto::time::Timestamp;
use midnight_ledger::semantics::TransactionResult;
use midnight_ledger::structure::{ProofVersioned, INITIAL_PARAMETERS};
use midnight_ledger::verify::ProofVerificationMode;
use midnight_onchain_runtime::cost_model::INITIAL_COST_MODEL;
use midnight_transient_crypto::proofs::{ParamsProverProvider, ProvingKeyMaterial, Zkir};
use minocrab_contracts::events::MISC_SIZE;
use minocrab_contracts::signet_contract;
use minocrab_zkir::v3::IrSource;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

mod support;

use support::proving::{peak_rss_bytes, ManagedKeys, V3ProvingProvider};
use support::signet_call::{
    bytesn_value, call_intent, call_prototype, deploy_singleton, managed_verifier_key, preimage_tx,
    respond_bidirectional_input, respond_bidirectional_misc, respond_input, respond_misc,
    sample_attestation, singleton_contract_state, ttl, tx_context, unbalanced_strictness,
    SIGNER_CIRCUITS,
};

const SIDES: [&str; 2] = ["minocrab", "compactc"];

const CORPUS_DIR: &str =
    "corpus/zkir/signet-midnight-integration-pr127/packages/signet-contract/src/signet-contract/zkir";

fn ir_of(side: &str, circuit: &str) -> IrSource {
    match side {
        "minocrab" => match circuit {
            "signBidirectional" => signet_contract::SignetContract::sign_bidirectional().ir,
            "respond" => signet_contract::SignetContract::respond().ir,
            "respondBidirectional" => signet_contract::SignetContract::respond_bidirectional().ir,
            other => panic!("unknown signer circuit {other}"),
        },
        "compactc" => {
            let path = format!("{}/../../{CORPUS_DIR}/{circuit}.zkir", env!("CARGO_MANIFEST_DIR"));
            minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
        }
        other => panic!("unknown side {other}"),
    }
}

// ---- the same call every signer gate builds --------------------------------

fn request_id() -> [u8; 32] {
    let mut rid = [0u8; 32];
    rid[..10].copy_from_slice(b"request-id");
    rid[31] = 0x9c;
    rid
}

fn fill(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, byte) in b.iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8).wrapping_mul(13);
    }
    b
}

/// The Misc bytes and the typed argument value — `signet_real_proof.rs`'s
/// scenario, verbatim, so the statement priced here is the one the
/// construction gate proved PI-equal under both artifacts.
fn call_arguments(circuit: &str) -> (Vec<u8>, AlignedValue) {
    match circuit {
        "signBidirectional" => {
            let mut payload = [0u8; 128];
            for (i, b) in payload.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(7).wrapping_add(3);
            }
            let (rid, version) = (request_id(), 1u8);
            let name = signet_contract::SIGN_BIDIRECTIONAL_EVENT;
            let mut misc = vec![0u8; MISC_SIZE];
            misc[..name.len()].copy_from_slice(name.as_bytes());
            misc[32] = version;
            misc[33..65].copy_from_slice(&rid);
            misc[65..193].copy_from_slice(&payload);
            let input = AlignedValue::concat([
                &bytesn_value(32, &rid),
                &bytesn_value(1, &[version]),
                &bytesn_value(128, &payload),
            ]);
            (misc, input)
        }
        "respond" => {
            let (rid, x, y, s, recovery_id) = (request_id(), fill(0x11), fill(0x47), fill(0xa3), 1u8);
            (
                respond_misc(signet_contract::SIGNATURE_RESPONDED_EVENT, &rid, &x, &y, &s, recovery_id),
                respond_input(&rid, &x, &y, &s, recovery_id),
            )
        }
        "respondBidirectional" => {
            let (rid, x, y, s, recovery_id) = (request_id(), fill(0x11), fill(0x47), fill(0xa3), 1u8);
            let att = sample_attestation();
            (
                respond_bidirectional_misc(&rid, &att, &x, &y, &s, recovery_id),
                respond_bidirectional_input(&rid, &att, &x, &y, &s, recovery_id),
            )
        }
        other => panic!("unknown signer circuit {other}"),
    }
}

// ---- one cell ----------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Cell {
    circuit: String,
    side: String,
    k: u8,
    rows: usize,
    prover_key_bytes: usize,
    verifier_key_bytes: usize,
    keygen_s: f64,
    /// Median of `MINOCRAB_PROVE_ITERS` (default 3) `Transaction::prove`s.
    prove_s: f64,
    proof_bytes: usize,
    /// The sealed transaction, tagged-serialized: what goes over the wire.
    tx_bytes: usize,
    /// `well_formed` with `verify_contract_proofs` on, `Real` mode.
    well_formed_s: f64,
    apply_s: f64,
    /// `Transaction::cost(INITIAL_PARAMETERS)`, the cost model's inputs.
    cost_read_ps: u64,
    cost_compute_ps: u64,
    cost_block_usage: u64,
    cost_bytes_written: u64,
    /// `Transaction::fees(INITIAL_PARAMETERS)`, in SPECKS (decimal string:
    /// u128 does not survive every JSON reader).
    fee_specks: String,
    peak_rss_bytes: u64,
}

fn params_provider() -> MidnightDataProvider {
    MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("the KZG parameter provider initialises")
}

async fn measure(side: &str, circuit: &str) -> Cell {
    let params = params_provider();
    let tblock = Timestamp::from_secs(0);

    // keygen from this side's IR.
    let ir = ir_of(side, circuit);
    let model = ir.model();
    let (k, rows) = (model.k(), model.rows());
    params.get_params(k).await.expect("KZG params for this k");
    let t = Instant::now();
    let (pk, vk) = ir.keygen(&params).await.expect("keygen");
    let keygen_s = t.elapsed().as_secs_f64();

    let ser = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut buf = Vec::new();
        f(&mut buf);
        buf
    };
    let pk_bytes = ser(&|b: &mut Vec<u8>| midnight_serialize::tagged_serialize(&pk, b).expect("pk"));
    let vk_bytes = ser(&|b: &mut Vec<u8>| midnight_serialize::tagged_serialize(&vk, b).expect("vk"));
    let ir_bytes = ser(&|b: &mut Vec<u8>| midnight_serialize::tagged_serialize(&ir, b).expect("ir"));
    let mut keys = ManagedKeys::default();
    keys.0.insert(
        circuit.to_string(),
        ProvingKeyMaterial {
            prover_key: pk_bytes.clone(),
            verifier_key: vk_bytes.clone(),
            ir_source: ir_bytes,
        },
    );

    // Deploy under THIS side's key for the circuit under test (the other two
    // operations carry the managed keys and are never called here).
    let vk_for_deploy = vk.clone();
    let (ledger, address) = deploy_singleton(
        singleton_contract_state(|c| {
            Some(if c == circuit { vk_for_deploy.clone() } else { managed_verifier_key(c) })
        }),
        tblock,
    );

    // The call, proved `iters` times; the median is the number.
    let (misc, input) = call_arguments(circuit);
    let build = || {
        let proto = call_prototype(circuit, address, input.clone(), &misc);
        preimage_tx(call_intent(vec![proto], ttl(tblock)))
    };
    let iters: usize = std::env::var("MINOCRAB_PROVE_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
    let mut times = Vec::with_capacity(iters);
    let mut proven = None;
    for i in 0..iters {
        let provider = V3ProvingProvider {
            rng: StdRng::seed_from_u64(0x5052_4f56_45 + i as u64),
            keys: &keys,
            params: &params,
        };
        let t = Instant::now();
        let p = build()
            .prove(provider, &INITIAL_COST_MODEL)
            .await
            .unwrap_or_else(|e| panic!("{side}/{circuit}: proving failed: {e:?}"));
        times.push(t.elapsed().as_secs_f64());
        proven = Some(p);
    }
    times.sort_by(f64::total_cmp);
    let prove_s = times[times.len() / 2];
    let sealed = proven.expect("at least one prove").seal(StdRng::seed_from_u64(0x5345_414c));

    // Sizes: the proof inside the call, and the whole sealed transaction.
    let mut proof_bytes = 0usize;
    for (_, call) in sealed.calls() {
        proof_bytes += match &call.proof {
            ProofVersioned::V2(p) | ProofVersioned::V3(p) => p.0.len(),
            // `#[non_exhaustive]` upstream: a proof version this gate has
            // never seen is a reason to stop, not to guess (notes/version-bump.org).
            other => panic!("unknown ProofVersioned variant: {other:?}"),
        };
    }
    let tx_bytes = ser(&|b: &mut Vec<u8>| midnight_serialize::tagged_serialize(&sealed, b).expect("tx")).len();

    // The chain's side: verify (Real), apply, cost, fee.
    let mut strict = unbalanced_strictness();
    strict.verify_contract_proofs = true;
    strict.proof_verification_mode = ProofVerificationMode::Real;
    let t = Instant::now();
    let vtx = sealed
        .well_formed(&ledger, strict, tblock)
        .unwrap_or_else(|e| panic!("{side}/{circuit}: the proven transaction was rejected: {e:?}"));
    let well_formed_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let (_after, result) = ledger.apply(&vtx, &tx_context(&ledger, tblock));
    let apply_s = t.elapsed().as_secs_f64();
    assert!(
        matches!(result, TransactionResult::Success(_)),
        "{side}/{circuit}: the proven transaction did not apply: {result:?}"
    );
    let cost = sealed
        .cost(&INITIAL_PARAMETERS, false)
        .unwrap_or_else(|e| panic!("{side}/{circuit}: cost: {e:?}"));
    let fee = sealed
        .fees(&INITIAL_PARAMETERS, false)
        .unwrap_or_else(|e| panic!("{side}/{circuit}: fees: {e:?}"));

    Cell {
        circuit: circuit.to_string(),
        side: side.to_string(),
        k,
        rows,
        prover_key_bytes: pk_bytes.len(),
        verifier_key_bytes: vk_bytes.len(),
        keygen_s,
        prove_s,
        proof_bytes,
        tx_bytes,
        well_formed_s,
        apply_s,
        cost_read_ps: cost.read_time.into_picoseconds(),
        cost_compute_ps: cost.compute_time.into_picoseconds(),
        cost_block_usage: cost.block_usage,
        cost_bytes_written: cost.bytes_written,
        fee_specks: fee.to_string(),
        peak_rss_bytes: peak_rss_bytes(),
    }
}

/// One cell, selected by `MINOCRAB_POSTING_CELL=<side>:<circuit>`; prints
/// the JSON line the parent collects. Run by [`posting_benchmark`], one
/// subprocess per cell, so each cell's peak RSS is its own.
#[test]
#[ignore = "one benchmark cell; driven by posting_benchmark through MINOCRAB_POSTING_CELL"]
fn measure_one_cell() {
    let Ok(cell) = std::env::var("MINOCRAB_POSTING_CELL") else {
        eprintln!("MINOCRAB_POSTING_CELL is not set; nothing to measure (run posting_benchmark)");
        return;
    };
    let (side, circuit) = cell.split_once(':').expect("<side>:<circuit>");
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("a tokio runtime");
    let measured = runtime.block_on(measure(side, circuit));
    println!("MINOCRAB_POSTING_RESULT {}", serde_json::to_string(&measured).expect("json"));
}

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn mb(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / 1e6)
}

fn render(cells: &[Cell]) -> String {
    let mut out = String::new();
    out.push_str("| circuit | side | k | rows | prover key MB | keygen s | prove s | peak RSS MB | proof B | tx B | well_formed s | fee SPECKS | compute ms | read ms | block usage B | written B |\n");
    out.push_str("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for c in cells {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {:.3} | {:.3} | {} | {} | {} | {:.4} | {} | {:.3} | {:.3} | {} | {} |\n",
            c.circuit,
            c.side,
            c.k,
            c.rows,
            mb(c.prover_key_bytes as u64),
            c.keygen_s,
            c.prove_s,
            mb(c.peak_rss_bytes),
            c.proof_bytes,
            c.tx_bytes,
            c.well_formed_s,
            c.fee_specks,
            c.cost_compute_ps as f64 / 1e9,
            c.cost_read_ps as f64 / 1e9,
            c.cost_block_usage,
            c.cost_bytes_written,
        ));
    }
    out
}

/// The orchestrator: every circuit × side in a fresh subprocess, then the
/// table. Sides can be restricted with `MINOCRAB_POSTING_SIDES=minocrab`.
#[test]
#[ignore = "real proving of both artifact sets: run under --release, and it needs the KZG params on disk"]
fn posting_benchmark() {
    let exe = std::env::current_exe().expect("the test binary's path");
    let sides: Vec<String> = std::env::var("MINOCRAB_POSTING_SIDES")
        .map(|s| s.split(',').map(str::to_string).collect())
        .unwrap_or_else(|_| SIDES.iter().map(|s| s.to_string()).collect());
    let out_dir = repo_root().join("target/bench");
    std::fs::create_dir_all(&out_dir).expect("target/bench");
    let mut cells = Vec::new();
    for circuit in SIGNER_CIRCUITS {
        for side in &sides {
            eprint!("{circuit:>22} {side:>9} … ");
            let t = Instant::now();
            let output = std::process::Command::new(&exe)
                .args(["--ignored", "--exact", "measure_one_cell", "--nocapture"])
                .env("MINOCRAB_POSTING_CELL", format!("{side}:{circuit}"))
                .output()
                .expect("spawn the cell");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let line = stdout
                .lines()
                .find_map(|l| l.strip_prefix("MINOCRAB_POSTING_RESULT "))
                .unwrap_or_else(|| {
                    panic!(
                        "{side}/{circuit}: no result line\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
                        String::from_utf8_lossy(&output.stderr)
                    )
                });
            let cell: Cell = serde_json::from_str(line).expect("a Cell");
            eprintln!(
                "k={} prove {:.3}s rss {} MB fee {} ({:.0}s)",
                cell.k,
                cell.prove_s,
                mb(cell.peak_rss_bytes),
                cell.fee_specks,
                t.elapsed().as_secs_f64()
            );
            cells.push(cell);
        }
    }
    let jsonl: String = cells.iter().map(|c| serde_json::to_string(c).unwrap() + "\n").collect();
    std::fs::write(out_dir.join("posting.jsonl"), jsonl).expect("posting.jsonl");
    let table = render(&cells);
    std::fs::write(out_dir.join("posting.md"), &table).expect("posting.md");
    println!("\n{table}");

    // The claims the module header makes, checked on the numbers: for each
    // circuit, both sides paid the SAME fee, the same cost-model inputs and
    // the same proof size.
    if sides.len() == 2 {
        for circuit in SIGNER_CIRCUITS {
            let of = |side: &str| cells.iter().find(|c| c.circuit == circuit && c.side == side).unwrap();
            let (a, b) = (of(&sides[0]), of(&sides[1]));
            assert_eq!(a.fee_specks, b.fee_specks, "{circuit}: the fee differs between sides");
            assert_eq!(a.proof_bytes, b.proof_bytes, "{circuit}: the proof size differs between sides");
            assert_eq!(
                (a.cost_read_ps, a.cost_compute_ps, a.cost_block_usage, a.cost_bytes_written),
                (b.cost_read_ps, b.cost_compute_ps, b.cost_block_usage, b.cost_bytes_written),
                "{circuit}: the cost-model inputs differ between sides"
            );
        }
    }
}
