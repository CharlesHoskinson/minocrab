//! `EntryPoint` against upstream, over the whole corpus.
//!
//! The entry-point hash is the ledger's half of a cross-contract call: a
//! `claimContractCall` is accepted only if `(address, entry_point, comm)`
//! matches what the callee's transaction claims (onchain-runtime
//! `structure.rs`). It is therefore not a value we may define — and
//! [`minocrab_ledger::ep_hash`] does not: it calls
//! `EntryPointBuf::ep_hash`.
//!
//! What is left to test is that the CALL is the right one and that our FAB
//! limb split of the result matches the `Bytes<32>` convention the claim's
//! `rt-aligned-concat` uses. Both are checked here against the real thing:
//!
//!  - the hash, for EVERY circuit name in EVERY corpus `contract-info.json`
//!    (312 artifacts), against an independently constructed
//!    `EntryPointBuf`, and against `persistent_commit` with the domain
//!    separator spelled out by hand;
//!  - the limbs, against the `AlignedValue` the ledger actually builds from
//!    that hash.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_base_crypto::hash::{persistent_commit, HashOutput};
use midnight_onchain_state::state::EntryPointBuf;
use midnight_transient_crypto::fab::ValueReprAlignedValue;
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::Fr;
use minocrab_ledger::{ep_hash, ep_limbs, EntryPoint};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/zkir")
}

/// Every `contract-info.json` under `corpus/zkir`.
fn contract_infos(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            contract_infos(&path, out);
        } else if path.file_name().is_some_and(|n| n == "contract-info.json") {
            out.push(path);
        }
    }
}

/// The `circuits[].name` of every corpus artifact, deduplicated.
fn corpus_circuit_names() -> (usize, BTreeSet<String>) {
    let mut files = Vec::new();
    contract_infos(&corpus_root(), &mut files);
    let mut names = BTreeSet::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("contract-info.json reads");
        let info: serde_json::Value = serde_json::from_str(&text).expect("contract-info parses");
        let circuits = info
            .get("circuits")
            .and_then(|c| c.as_array())
            .unwrap_or_else(|| panic!("{} has no circuits array", file.display()));
        for circuit in circuits {
            let name = circuit
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or_else(|| panic!("{} has an unnamed circuit", file.display()));
            names.insert(name.to_string());
        }
    }
    (files.len(), names)
}

/// THE SWEEP: our hash is upstream's, for every circuit name compactc has
/// ever emitted in the corpus.
#[test]
fn ep_hash_matches_upstream_for_every_corpus_circuit() {
    let (artifacts, names) = corpus_circuit_names();
    // 312 through M22; +3 with the aa-midnight-evm-experiment source (the
    // AA manager and its two test-support minters, 2026-08-26); +1 at the
    // M31 compactc bump (0.33.0-rc.2 → 0.34.0), where
    // compact/examples/types/examples.compact started compiling because
    // Uint<0> became a legal type (CHANGELOG 0.33.111). The hash rule
    // itself did not move: every circuit name in the corpus, the new
    // source's included, still hashes to upstream's entry point. +3 at
    // M43 A: the second signet-midnight-integration pin (pr127, e9350c4),
    // the singleton's three circuits at PR #127.
    assert_eq!(
        artifacts, 319,
        "the corpus artifact count moved; re-read notes/corpus-sources.org before \
         refreshing this number"
    );
    assert!(
        names.len() > 100,
        "only {} distinct circuit names — the walk is not finding the corpus",
        names.len()
    );

    for name in &names {
        let upstream = EntryPointBuf::from(name.as_bytes()).ep_hash();
        assert_eq!(ep_hash(name), upstream.0, "ep_hash({name})");

        // …and the derivation upstream documents, spelled out here so a
        // change to it fails loudly rather than silently re-keying every
        // call: persistent_commit(name, "midnight:entry-point" padded to
        // 32 bytes with zeros).
        let mut sep = [0u8; 32];
        sep[..b"midnight:entry-point".len()].copy_from_slice(b"midnight:entry-point");
        assert_eq!(
            ep_hash(name),
            persistent_commit(name.as_bytes(), HashOutput(sep)).0,
            "the domain separator for {name}"
        );
    }
}

/// The corpus's own cross-contract names, pinned as concrete vectors: these
/// are the entry points M12 stages 2-4 actually claim.
#[test]
fn the_called_entry_points_are_stable_values() {
    for name in [
        "signBidirectional",
        "respond",
        "respondBidirectional",
        "deposit",
        "depositEmit",
        "depositBig",
        "notify",
        "confirmRequest",
    ] {
        let ours = ep_hash(name);
        assert_eq!(ours, EntryPointBuf::from(name.as_bytes()).ep_hash().0);
        assert_ne!(ours, [0u8; 32], "{name} hashed to zero");
    }

    // Distinct names, distinct hashes — the property `callOnce`/`callEmit`
    // rely on (same circuit, different claimed entry point).
    assert_ne!(ep_hash("deposit"), ep_hash("depositEmit"));
}

/// `EntryPoint`'s const constructor and its accessors agree with the free
/// functions.
#[test]
fn the_const_handle_agrees_with_the_free_functions() {
    const EP: EntryPoint = EntryPoint::new("signBidirectional");
    assert_eq!(EP.name(), "signBidirectional");
    assert_eq!(EP.hash(), ep_hash("signBidirectional"));
    assert_eq!(EP.limbs(), ep_limbs("signBidirectional"));
}

/// The `[hi, lo]` split is the ledger's own `Bytes<32>` field
/// representation: build the `AlignedValue` a claim carries and read its
/// limbs back.
#[test]
fn the_limbs_are_the_ledgers_own_bytes32_field_repr() {
    for name in ["deposit", "signBidirectional", "respondBidirectional"] {
        let hash = ep_hash(name);
        let av = AlignedValue::new(
            Value(vec![ValueAtom(hash.to_vec()).normalize()]),
            Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
                length: 32,
            })]),
        )
        .expect("a Bytes<32> value");
        let mut repr: Vec<Fr> = Vec::new();
        ValueReprAlignedValue(av).field_repr(&mut repr);
        assert_eq!(repr, ep_limbs(name).to_vec(), "limbs of {name}");
    }
}
