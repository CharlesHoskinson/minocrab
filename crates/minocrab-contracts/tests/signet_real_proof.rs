//! M29 rung E — THE REAL-PROVING GATE. The first real proof in this test
//! suite.
//!
//! `#[ignore]`d by default and meant for `--release`, like `row_snapshot`:
//!
//! ```console
//! cargo test --release -p minocrab-contracts --test signet_real_proof -- --ignored --nocapture
//! ```
//!
//! Everything before this rung stops at the public inputs. `IrSource::check`
//! says the preimage satisfies the circuit; the differential says both
//! artifacts agree on the PI vector; rung D says the ledger applies the call
//! — but nothing anywhere had ever produced a PROOF from a
//! ledger-constructed preimage and had the ledger VERIFY it against a
//! DEPLOYED verifier key. That is this rung, for all three signer circuits:
//!
//! 1. keygen from OUR IR (`signet_contract::*().ir`), parameters from
//!    `MidnightDataProvider` (pre-warmed under `~/.cache/midnight/zk-params`);
//! 2. assert the verifier key that came out is byte-identical to the
//!    COMMITTED `crates/signet-artifacts/managed/keys/<circuit>.verifier`, so
//!    the key this gate deploys is the artifact M29 A ships and not a
//!    look-alike;
//! 3. `ContractDeploy` under those keys, into a `LedgerState`;
//! 4. build the call the rung-C way, then `Transaction::prove` through an
//!    IN-PROCESS `ProvingProvider` ([`V3ProvingProvider`]), and `seal`;
//! 5. `well_formed` with `verify_contract_proofs` ON in
//!    `ProofVerificationMode::Real`, against the deployed key — then `apply`.
//!
//! The negative control is in the same test: the same three proofs are also
//! offered to a singleton deployed with the keys PERMUTED (respond's
//! operation carrying signBidirectional's verifier key, and so on), and
//! `well_formed` must reject every one. Without it, step 5 passing would be
//! consistent with nothing being verified at all.
//!
//! # Why the proving provider is written here
//!
//! `midnight_ledger::test_utilities` has one — `CombinedProofProvider` — but
//! it is a private struct behind the ledger's `test-utilities` + `proving`
//! features, and its resolver is `ledger::prove::Resolver`, which owns a
//! `ZswapResolver` and a `DustResolver`: network-fetched parameter sets this
//! gate has no use for, since the transaction carries no zswap offer and no
//! dust action. So [`V3ProvingProvider`] is a MECHANICAL TRANSLATION of that
//! struct's v3 arm (`ledger/src/test_utilities.rs:749-818`): resolve the key
//! material, load the `ir-source[v3-generic]` `IrSource` from it, and hand
//! the preimage to `ProofPreimage::prove::<zkir_v3::IrSource>` — which is
//! also the call `crates/minocrab-bench` makes, one layer down.
//!
//! Proving is therefore entirely in process: no proof server, no child
//! process, and no network once the KZG parameters are on disk. That is the
//! claim notes/mpc-publisher.org §2 makes about the port, exercised.
//!
//! # What this gate does NOT prove
//!
//! Nothing about fees: `enforce_balancing` and `enforce_limits` are off, and
//! no DUST wallet exists in this workspace. Nothing about the network: the
//! transaction is never submitted. And the deployed key is ours by
//! construction — that a real chain will one day carry it is deploy
//! tooling's job, tracked outside this repo.

use std::time::Instant;

use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use midnight_base_crypto::fab::AlignedValue;
use midnight_base_crypto::time::Timestamp;
use midnight_ledger::semantics::TransactionResult;
use midnight_ledger::verify::ProofVerificationMode;
use midnight_onchain_runtime::cost_model::INITIAL_COST_MODEL;
use midnight_transient_crypto::proofs::{ParamsProverProvider, ProvingKeyMaterial, Zkir};
use minocrab::v3::Compiled3;
use minocrab_contracts::events::MISC_SIZE;
use minocrab_contracts::signet_contract;
use rand::rngs::StdRng;
use rand::SeedableRng;

mod support;

use support::proving::{peak_rss_bytes, ManagedKeys, V3ProvingProvider};
use support::signet_call::{
    bytesn_value, call_intent, call_prototype, deploy_singleton, managed_verifier_key, preimage_tx,
    respond_bidirectional_input, respond_bidirectional_misc, respond_input, respond_misc,
    sample_attestation, singleton_contract_state, ttl, tx_context, unbalanced_strictness,
    SIGNER_CIRCUITS,
};

// The in-process proving provider and the RSS probe live in
// `support::proving` since M43 D, shared with `signet_posting.rs`.

fn params_provider() -> MidnightDataProvider {
    MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("the KZG parameter provider initialises")
}

// ---- the calls under proof -------------------------------------------------

/// A signer circuit under test: its Compact name and how to build its IR.
struct Subject {
    circuit: &'static str,
    build: fn() -> Compiled3,
}

fn subjects() -> Vec<Subject> {
    vec![
        Subject { circuit: "signBidirectional", build: signet_contract::SignetContract::sign_bidirectional },
        Subject { circuit: "respond", build: signet_contract::SignetContract::respond },
        Subject { circuit: "respondBidirectional", build: signet_contract::SignetContract::respond_bidirectional },
    ]
}

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

/// The Misc bytes and the typed argument value for one circuit — the same
/// scenario values `tests/signet_construction.rs` runs its differential on,
/// so what this rung adds is the proof, not new arguments.
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
            let (rid, x, y, s, recovery_id) =
                (request_id(), fill(0x11), fill(0x47), fill(0xa3), 1u8);
            (
                respond_misc(signet_contract::SIGNATURE_RESPONDED_EVENT, &rid, &x, &y, &s, recovery_id),
                respond_input(&rid, &x, &y, &s, recovery_id),
            )
        }
        "respondBidirectional" => {
            let (rid, x, y, s, recovery_id) =
                (request_id(), fill(0x11), fill(0x47), fill(0xa3), 1u8);
            let att = sample_attestation();
            (
                respond_bidirectional_misc(&rid, &att, &x, &y, &s, recovery_id),
                respond_bidirectional_input(&rid, &att, &x, &y, &s, recovery_id),
            )
        }
        other => panic!("unknown signer circuit {other}"),
    }
}

/// The permuted key assignment for the negative control: each circuit's
/// operation carries the NEXT circuit's verifier key.
fn permuted_key(circuit: &str) -> midnight_transient_crypto::proofs::VerifierKey {
    let i = SIGNER_CIRCUITS
        .iter()
        .position(|c| *c == circuit)
        .expect("a signer circuit");
    managed_verifier_key(SIGNER_CIRCUITS[(i + 1) % SIGNER_CIRCUITS.len()])
}

// ---- the gate --------------------------------------------------------------

/// keygen → deploy → build → prove → seal → `well_formed` (proofs verified,
/// Real mode) → `apply`, for all three signer circuits, in one process; and
/// the same proofs rejected against a permuted-key deployment.
#[test]
#[ignore = "real proving: run under --release, and it needs the KZG params on disk"]
fn every_signer_circuit_proves_and_verifies_against_the_deployed_key() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime");
    runtime.block_on(async {
        let params = params_provider();
        let tblock = Timestamp::from_secs(0);
        let baseline_rss = peak_rss_bytes();
        println!("baseline peak RSS: {:.1} MB", baseline_rss as f64 / 1e6);

        // 1 + 2. keygen from our IR; the key must be the committed one.
        let mut keys = ManagedKeys::default();
        for subject in subjects() {
            let ir = (subject.build)().ir;
            let model = ir.model();
            let k = model.k();
            // Warm the parameter cache outside the timing, as
            // crates/minocrab-bench does.
            params.get_params(k).await.expect("KZG params for this k");

            let t = Instant::now();
            let (pk, vk) = ir.keygen(&params).await.expect("keygen");
            let keygen_s = t.elapsed().as_secs_f64();

            let ser = |value: &dyn Fn(&mut Vec<u8>)| {
                let mut buf = Vec::new();
                value(&mut buf);
                buf
            };
            let vk_bytes = ser(&|buf: &mut Vec<u8>| {
                midnight_serialize::tagged_serialize(&vk, buf).expect("vk serializes")
            });
            let committed = ser(&|buf: &mut Vec<u8>| {
                midnight_serialize::tagged_serialize(&managed_verifier_key(subject.circuit), buf)
                    .expect("committed vk serializes")
            });
            assert_eq!(
                vk_bytes, committed,
                "{}: keygen from our IR did not reproduce the COMMITTED managed verifier key",
                subject.circuit
            );

            let mut pk_bytes = Vec::new();
            midnight_serialize::tagged_serialize(&pk, &mut pk_bytes).expect("pk serializes");
            let mut ir_bytes = Vec::new();
            midnight_serialize::tagged_serialize(&ir, &mut ir_bytes).expect("ir serializes");
            println!(
                "{}: k={k}, rows={}, keygen {keygen_s:.3} s, prover key {:.1} MB",
                subject.circuit,
                model.rows(),
                pk_bytes.len() as f64 / 1e6
            );
            keys.0.insert(
                subject.circuit.to_string(),
                ProvingKeyMaterial {
                    prover_key: pk_bytes,
                    verifier_key: vk_bytes,
                    ir_source: ir_bytes,
                },
            );
        }

        // 3. Deploy: the honest singleton, and the permuted-key one the
        // negative control offers the same proofs to.
        let (ledger, address) =
            deploy_singleton(singleton_contract_state(|c| Some(managed_verifier_key(c))), tblock);
        let (wrong_ledger, wrong_address) =
            deploy_singleton(singleton_contract_state(|c| Some(permuted_key(c))), tblock);

        // Proofs ON, in Real mode: the whole point of the rung.
        let mut strict = unbalanced_strictness();
        strict.verify_contract_proofs = true;
        strict.proof_verification_mode = ProofVerificationMode::Real;

        let mut previous_rss = baseline_rss;
        for subject in subjects() {
            let (misc, input) = call_arguments(subject.circuit);

            let prove_at = |at| {
                let proto = call_prototype(subject.circuit, at, input.clone(), &misc);
                preimage_tx(call_intent(vec![proto], ttl(tblock)))
            };

            // 4. Prove in process, then seal.
            let tx = prove_at(address);
            let provider = V3ProvingProvider {
                rng: StdRng::seed_from_u64(0x5052_4f56_45),
                keys: &keys,
                params: &params,
            };
            let t = Instant::now();
            let proven = tx
                .prove(provider, &INITIAL_COST_MODEL)
                .await
                .unwrap_or_else(|e| panic!("{}: proving failed: {e:?}", subject.circuit));
            let prove_s = t.elapsed().as_secs_f64();
            let sealed = proven.seal(StdRng::seed_from_u64(0x5345_414c));

            // 5. well_formed with proofs verified, then apply.
            let t = Instant::now();
            let vtx = sealed.well_formed(&ledger, strict, tblock).unwrap_or_else(|e| {
                panic!("{}: the proven transaction was rejected: {e:?}", subject.circuit)
            });
            let verify_s = t.elapsed().as_secs_f64();

            let (_after, result) = ledger.apply(&vtx, &tx_context(&ledger, tblock));
            assert!(
                matches!(result, TransactionResult::Success(_)),
                "{}: the proven transaction did not apply: {result:?}",
                subject.circuit
            );

            let rss = peak_rss_bytes();
            println!(
                "{}: prove {prove_s:.3} s, well_formed(verify) {verify_s:.3} s, \
                 peak RSS {:.1} MB (+{:.1} MB)",
                subject.circuit,
                rss as f64 / 1e6,
                rss.saturating_sub(previous_rss) as f64 / 1e6
            );
            previous_rss = rss.max(previous_rss);

            // The negative control: the same circuit, proved honestly, at a
            // singleton whose operation carries ANOTHER circuit's verifier
            // key. `well_formed` must say no.
            let wrong_tx = prove_at(wrong_address);
            let provider = V3ProvingProvider {
                rng: StdRng::seed_from_u64(0x5052_4f56_45),
                keys: &keys,
                params: &params,
            };
            let wrong_sealed = wrong_tx
                .prove(provider, &INITIAL_COST_MODEL)
                .await
                .unwrap_or_else(|e| panic!("{}: proving failed: {e:?}", subject.circuit))
                .seal(StdRng::seed_from_u64(0x5345_414c));
            let rejected = wrong_sealed.well_formed(&wrong_ledger, strict, tblock);
            assert!(
                rejected.is_err(),
                "{}: a proof was accepted against another circuit's verifier key — \
                 verification is not actually happening",
                subject.circuit
            );
            println!("{}: permuted-key deployment rejects, as it must", subject.circuit);
        }
        println!("run peak RSS: {:.1} MB", peak_rss_bytes() as f64 / 1e6);
    });
}

/// The managed directory's three circuits are the three this gate proves —
/// stated so a fourth signer circuit cannot appear without this file
/// noticing. Cheap, so it runs in the ordinary `cargo test` loop.
#[test]
fn the_gate_covers_every_managed_signer_circuit() {
    let mut ours: Vec<&str> = subjects().iter().map(|s| s.circuit).collect();
    ours.sort_unstable();
    let mut managed: Vec<&str> = SIGNER_CIRCUITS.to_vec();
    managed.sort_unstable();
    assert_eq!(ours, managed);
    // And the permutation the negative control uses really does move every
    // circuit's key.
    for circuit in SIGNER_CIRCUITS {
        assert_ne!(
            permuted_key(circuit),
            managed_verifier_key(circuit),
            "{circuit}: the permutation left the key in place"
        );
    }
}
