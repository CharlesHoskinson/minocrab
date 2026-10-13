//! Shared test support. Not a test target (lives in a subdirectory).
//!
//! Compiled into every test binary that declares `mod support`, each of
//! which uses only the part it needs — hence the blanket `dead_code`
//! allowance, and the same allowance for the re-exports through which
//! `signet_call` now hands on `minocrab-publisher`'s construction path
//! (M30 rung A): a test binary that needs three of them still names the
//! module, not the item.
#![allow(dead_code, unused_imports)]

// The Signet singleton's calls, built through the LEDGER's own
// `ContractCallPrototype`/`construct_proof` (M29 rung C). Every singleton
// proof preimage in the suite comes from here.
pub mod proving;
pub mod signet_call;

use midnight_transient_crypto::proofs::ProofPreimage;

use minocrab::v3::Compiled3;
use minocrab_zkir::v3::{to_zkir_string, IrSource};
use minocrab_contracts::{
    adts, attest, bounded, bounded_ledger, coins, kernel_tokens, erc20_vault, erc20_vault_pending, events, events_borsh, hashing, manager, mint_tokens,
    nested, opaque,
    serde_builtin, signet_contract, test_caller, treasury, xcall, xcall_with_payment,
    xcontract_events, xcontract_events_borsh,
};

/// A circuit under snapshot: its name and how to build it.
pub type Circuit = (&'static str, fn() -> Compiled3);

/// A file under `crates/minocrab-contracts/tests/`.
pub fn test_source(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join(name)
}

/// Replace a snapshot table's generated region, in place.
///
/// The snapshot regenerators WRITE their table back into their own source
/// file instead of printing it for a human to paste. A toolchain bump moves
/// several snapshots at once (M8, notes/version-bump.org), and `./bump.sh
/// accept` runs every regenerator in one step — a step that has to end with
/// a reviewable `git diff`, not with paste instructions.
///
/// `body` replaces every line strictly between the two marker lines, whose
/// own indentation is preserved. Each marker must appear exactly once.
pub fn rewrite_generated_region(path: &std::path::Path, body: &str) {
    // Assembled rather than written literally, so that the markers occur
    // exactly once in a file this function rewrites.
    let begin = format!("// {} BEGIN", "GENERATED");
    let end = format!("// {} END", "GENERATED");
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{} is not readable: {e}", path.display()));
    let at = |marker: &str| {
        let first = text
            .find(marker)
            .unwrap_or_else(|| panic!("{} has no `{marker}` marker", path.display()));
        assert!(
            text[first + marker.len()..].find(marker).is_none(),
            "{} has more than one `{marker}` marker",
            path.display()
        );
        first
    };
    let (begin_at, end_at) = (at(&begin), at(&end));
    assert!(begin_at < end_at, "{}: the markers are the wrong way round", path.display());
    // From just past the BEGIN marker's newline to the start of the line
    // carrying the END marker.
    let from = begin_at + text[begin_at..].find('\n').expect("the begin marker ends its line") + 1;
    let to = text[..end_at].rfind('\n').expect("the end marker is not on line 1") + 1;

    let mut out = String::with_capacity(text.len());
    out.push_str(&text[..from]);
    out.push_str(body);
    out.push_str(&text[to..]);
    std::fs::write(path, out).unwrap_or_else(|e| panic!("{} is not writable: {e}", path.display()));
    println!("wrote {}", path.display());
}

// ---- the ZKIR dump, and the diff that reads it ------------------------------

/// A circuit's serialized ZKIR, ONE INSTRUCTION PER LINE.
///
/// Exactly [`to_zkir_string`]'s JSON, split: the first line is the object
/// without its `instructions` (version, input schema, output types, the
/// communications-commitment flag), then one line per instruction in order.
/// Nothing is dropped, so equality of these lines is equality of the IR —
/// which is what lets the same rendering serve the byte-comparison instrument
/// (`zkir_dump`) and the line diff a snapshot failure prints.
pub fn zkir_lines(ir: &IrSource) -> Vec<String> {
    let text = to_zkir_string(ir).expect("the IR serializes");
    let mut value: serde_json::Value =
        serde_json::from_str(&text).expect("its own output parses back");
    let object = value
        .as_object_mut()
        .expect("a serialized IrSource is a JSON object");
    let instructions = object
        .remove("instructions")
        .expect("a serialized IrSource carries its instructions");
    let mut lines = vec![serde_json::to_string(&value).expect("the header re-serializes")];
    lines.extend(
        instructions
            .as_array()
            .expect("`instructions` is an array")
            .iter()
            .map(|i| serde_json::to_string(i).expect("an instruction re-serializes")),
    );
    lines
}

/// A circuit's file name in a dump directory: the name with `::` as `__`, so
/// a `diff -rq` names the circuit directly.
pub fn zkir_dump_name(circuit: &str) -> String {
    format!("{}.zkir", circuit.replace("::", "__"))
}

/// Write every circuit's [`zkir_lines`] into `dir`, one file each.
pub fn write_zkir_dump(dir: &std::path::Path) -> usize {
    std::fs::create_dir_all(dir).unwrap_or_else(|e| panic!("creating {}: {e}", dir.display()));
    let circuits = circuits();
    for (name, build) in &circuits {
        let mut text = zkir_lines(&build().ir).join("\n");
        text.push('\n');
        let path = dir.join(zkir_dump_name(name));
        std::fs::write(&path, text).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    }
    circuits.len()
}

/// Where `row_snapshot` looks for the previous run's dump: `$MINOCRAB_ZKIR_
/// BASELINE` if it is set (a directory `zkir_dump` produced at a chosen
/// commit), otherwise the copy the row snapshot keeps for itself under the
/// target directory.
pub fn zkir_baseline_dir() -> std::path::PathBuf {
    match std::env::var_os("MINOCRAB_ZKIR_BASELINE") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("zkir-baseline"),
    }
}

/// The longest-common-subsequence table of two line lists.
fn lcs_table(a: &[&str], b: &[&str]) -> Vec<Vec<usize>> {
    let mut lcs = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    lcs
}

/// A unified-style diff: `-` expected, `+` actual, ` ` unchanged.
///
/// One definition, used by `interface_snapshot`'s failure path (over
/// interface lines) and `row_snapshot`'s (over [`zkir_lines`]).
pub fn diff(expected: &[&str], actual: &[&str]) -> String {
    let lcs = lcs_table(expected, actual);
    let (mut i, mut j) = (0, 0);
    let mut out = String::new();
    while i < expected.len() && j < actual.len() {
        if expected[i] == actual[j] {
            out.push_str(&format!("      {}\n", expected[i]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push_str(&format!("    - {}\n", expected[i]));
            i += 1;
        } else {
            out.push_str(&format!("    + {}\n", actual[j]));
            j += 1;
        }
    }
    for line in &expected[i..] {
        out.push_str(&format!("    - {line}\n"));
    }
    for line in &actual[j..] {
        out.push_str(&format!("    + {line}\n"));
    }
    out
}

/// Beyond this many lines on either side, [`changed_lines`] stops using
/// [`diff`]: the LCS table is `(n+1)·(m+1)` `usize`s, which is nothing at the
/// ~300-instruction streams this workspace builds and gigabytes at a stream a
/// hundred times longer. A failing instrument must not exhaust memory, so the
/// fallback is a positional comparison — cruder (an insertion misaligns
/// everything after it) but bounded.
const LCS_LIMIT: usize = 5_000;

/// [`diff`] with the unchanged lines dropped and the result capped.
///
/// An instruction-level diff is mostly unchanged lines; what a failure needs
/// is the movement, so only the `-`/`+` lines survive and only the first
/// `max` of them are printed.
pub fn changed_lines(expected: &[&str], actual: &[&str], max: usize) -> String {
    let full = if expected.len().max(actual.len()) > LCS_LIMIT {
        positional_diff(expected, actual)
    } else {
        diff(expected, actual)
    };
    let changed: Vec<&str> = full
        .lines()
        .filter(|l| l.starts_with("    -") || l.starts_with("    +"))
        .collect();
    let mut out = String::new();
    for line in changed.iter().take(max) {
        out.push_str(line);
        out.push('\n');
    }
    if changed.len() > max {
        out.push_str(&format!(
            "    … {} more changed lines\n",
            changed.len() - max
        ));
    }
    out
}

/// [`diff`]'s shape without its table: index against index.
fn positional_diff(expected: &[&str], actual: &[&str]) -> String {
    let mut out = String::new();
    for i in 0..expected.len().max(actual.len()) {
        match (expected.get(i), actual.get(i)) {
            (Some(a), Some(b)) if a == b => out.push_str(&format!("      {a}\n")),
            (a, b) => {
                if let Some(a) = a {
                    out.push_str(&format!("    - {a}\n"));
                }
                if let Some(b) = b {
                    out.push_str(&format!("    + {b}\n"));
                }
            }
        }
    }
    out
}

/// Every circuit the workspace builds, in snapshot order. Shared by the
/// snapshot guards (`row_snapshot`, `interface_snapshot`) so both cover
/// exactly the same set; their frozen tables stay independent.
pub fn circuits() -> Vec<Circuit> {
    macro_rules! c {
        ($name:literal, $f:expr) => {
            ($name, { $f } as fn() -> Compiled3)
        };
    }

    // M32 A: every contract below is a `#[contract]` block now, so its
    // circuit set is DERIVED (`Contract::CIRCUITS`) rather than hand-listed —
    // a circuit added to one of them appears here without anyone editing
    // this file. `of()` names each entry `module::circuit`, matching what
    // this list named things by hand, so the frozen snapshots below don't
    // move. Two shapes can't be `of()`-derived in one call and stay in
    // their ORIGINAL positions instead (both gates row_snapshot and
    // interface_snapshot on): `erc20_vault_pending`, whose hand-written
    // order interleaves `approve_router` earlier than the source declares
    // it, and `xcall`, whose derived circuits sit between `entry()`-built
    // ones (see below). Listing those individually still calls through the
    // derived `Contract::circuit()` — only the BULK union is skipped.
    let mut listed: Vec<Circuit> = vec![
        // erc20-vault, the compat port of the seventeen-circuit vault
        // (signet-midnight-examples 0d9c1660, M28): PI-equal to compactc.
    ];
    listed.extend(of("erc20_vault", &erc20_vault::Vault::CIRCUITS));
    // M35 rung C: the vault on `Pending` — ten circuits (refund per slot).
    // Individually listed (not `of()`-unioned): the frozen snapshot orders
    // `approve_router` right after `claim`, but the source (preserved in
    // its EXISTING order, per the migration's zero-movement rule) declares
    // it after `refund_swap` — the two orders disagree, and the snapshot
    // wins.
    listed.extend([
        c!("erc20_vault_pending::initialize", || erc20_vault_pending::Vault::initialize()),
        c!("erc20_vault_pending::deposit", || erc20_vault_pending::Vault::deposit()),
        c!("erc20_vault_pending::claim", || erc20_vault_pending::Vault::claim()),
        c!("erc20_vault_pending::approve_router", || erc20_vault_pending::Vault::approve_router()),
        c!("erc20_vault_pending::withdraw", || erc20_vault_pending::Vault::withdraw()),
        c!("erc20_vault_pending::complete_withdraw", || erc20_vault_pending::Vault::complete_withdraw()),
        c!("erc20_vault_pending::refund_withdrawal", || erc20_vault_pending::Vault::refund_withdrawal()),
        c!("erc20_vault_pending::swap", || erc20_vault_pending::Vault::swap()),
        c!("erc20_vault_pending::complete_swap", || erc20_vault_pending::Vault::complete_swap()),
        c!("erc20_vault_pending::refund_swap", || erc20_vault_pending::Vault::refund_swap()),
        c!("erc20_vault_pending::approve_stata", || erc20_vault_pending::Vault::approve_stata()),
        c!("erc20_vault_pending::supply", || erc20_vault_pending::Vault::supply()),
        c!("erc20_vault_pending::complete_supply", || erc20_vault_pending::Vault::complete_supply()),
        c!("erc20_vault_pending::refund_supply", || erc20_vault_pending::Vault::refund_supply()),
        c!("erc20_vault_pending::redeem", || erc20_vault_pending::Vault::redeem()),
        c!("erc20_vault_pending::complete_redeem", || erc20_vault_pending::Vault::complete_redeem()),
        c!("erc20_vault_pending::refund_redeem", || erc20_vault_pending::Vault::refund_redeem()),
    ]);
    listed.extend(of("signet_contract", &signet_contract::SignetContract::CIRCUITS));
    listed.extend(of("attest", &attest::Attest::CIRCUITS));
    listed.extend([
        c!("events::base", || events::base()),
        c!("events::emit_n(1)", || events::emit_n(1)),
        c!("events::emit_n(2)", || events::emit_n(2)),
        c!("events::emit_n(4)", || events::emit_n(4)),
        // events, THROUGH THE BORSH API (M11 stage 6): byte-identical ZKIR to
        // the four above, so these rows must match them line for line.
        c!("events_borsh::base", || events_borsh::base()),
        c!("events_borsh::emit_n(1)", || events_borsh::emit_n(1)),
        c!("events_borsh::emit_n(2)", || events_borsh::emit_n(2)),
        c!("events_borsh::emit_n(4)", || events_borsh::emit_n(4)),
        // `hashing`/`keccak` (M9 phase 5): the width sweep is built through
        // [`hashing::control`] etc., a Rust VALUE parameterizing the family,
        // so it has no `#[circuit]` to derive from — see that module's docs.
        // `persistent_vec8`, the one fixed-width circuit in the family, IS
        // `#[contract]`-derived (below, via `of("hashing", ..)`).
        c!("hashing::control(32)", || hashing::control(32)),
        c!("hashing::control(64)", || hashing::control(64)),
        c!("hashing::control(128)", || hashing::control(128)),
        c!("hashing::control(256)", || hashing::control(256)),
        c!("hashing::control(1024)", || hashing::control(1024)),
        c!("hashing::persistent(32)", || hashing::persistent(32)),
        c!("hashing::persistent(64)", || hashing::persistent(64)),
        c!("hashing::persistent(128)", || hashing::persistent(128)),
        c!("hashing::persistent(256)", || hashing::persistent(256)),
        c!("hashing::persistent(1024)", || hashing::persistent(1024)),
        c!("hashing::keccak(64)", || hashing::keccak(64)),
        c!("hashing::keccak(128)", || hashing::keccak(128)),
        c!("hashing::keccak(256)", || hashing::keccak(256)),
        c!("hashing::transient(32)", || hashing::transient(32)),
        c!("hashing::transient(256)", || hashing::transient(256)),
        c!("hashing::transient(1024)", || hashing::transient(1024)),
    ]);
    listed.extend(of("hashing", &hashing::Hashing::CIRCUITS));
    // `xcall` (M5): individually listed, like `erc20_vault_pending` above —
    // its derived circuits (`local_base`, `call_emit`, `call_big`,
    // `target_deposit_big`) sit BETWEEN `entry()`-built family members
    // (`call_once`, `call_once_bound`, `call_twice`, `target_deposit`,
    // `target_deposit_emit`) in the frozen snapshot's order, so no single
    // `of()` call could reproduce it — the derived ones still call through
    // `Xcall::circuit()`.
    listed.extend([
        c!("xcall::local_base", || xcall::Xcall::local_base()),
        c!("xcall::call_once", || xcall::call_once()),
        // Byte-identical to call_once (xcall_differential pins it); listed so
        // the instruments see it under its own name (tests/circuit_closure.rs).
        c!("xcall::call_emit", || xcall::Xcall::call_emit()),
        c!("xcall::call_once_bound", || xcall::call_once_bound()),
        c!("xcall::call_twice", || xcall::call_twice()),
        c!("xcall::call_big", || xcall::Xcall::call_big()),
        c!("xcall::target_deposit", || xcall::target_deposit()),
        c!("xcall::target_deposit_emit", || xcall::target_deposit_emit()),
        c!("xcall::target_deposit_big", || xcall::Xcall::target_deposit_big()),
    ]);
    listed.extend(of("xcall_with_payment", &xcall_with_payment::XcallWithPayment::CIRCUITS));
    listed.extend(of("xcontract_events", &xcontract_events::XcontractEvents::CIRCUITS));
    listed.extend(of(
        "xcontract_events_borsh",
        &xcontract_events_borsh::XcontractEventsBorsh::CIRCUITS,
    ));
    listed.extend(of("mint_tokens", &mint_tokens::MintTokens::CIRCUITS));
    listed.extend(of("serde_builtin", &serde_builtin::SerdeBuiltin::CIRCUITS));
    listed.extend(of("test_caller", &test_caller::TestCaller::CIRCUITS));
    // `treasury` (M37 rung C): notes/evm-calls.org §0's target shape as a
    // real contract — the README's cross-chain example, compiled. Three
    // circuits, derived like every other `#[contract]` block.
    listed.extend(of("treasury", &treasury::Treasury::CIRCUITS));
    // `bounded.compact` (M14): Compact's `Uint<0..n>` at every shape the
    // bound can take, one circuit each. The only block here whose Compact
    // source is OURS rather than the corpus's — no compiled corpus
    // artifact carries a non-power-of-two bound
    // (tests/bounded_differential.rs has the scan).
    listed.extend(of("bounded", &bounded::Bounded::CIRCUITS));
    // `bounded_ledger.compact` (M31): a `Uint<0..1>` in LEDGER position —
    // compactc issue #588 gives it a one-byte alignment there, where
    // `bounded`'s own `b1` (an ARGUMENT position probe) sees no change
    // (tests/bounded_ledger_differential.rs has the reading).
    listed.extend(of("bounded_ledger", &bounded_ledger::BoundedLedger::CIRCUITS));
    // `opaque.compact` (M15): Compact's `Opaque<'ts-type'>` in every
    // position it can occupy, plus the two CURVE POINT types, which
    // compactc's ABI also spells `Opaque`. Ours rather than the corpus's
    // for the same reason as `bounded` above: the corpus's 74 `Opaque`
    // nodes are all in v2 artifacts except four `Secp256k1Point`s
    // (tests/opaque_differential.rs has the scan).
    listed.extend(of("opaque", &opaque::OpaqueLedger::CIRCUITS));
    // `adts.compact` (M16): every ledger-ADT operation Compact exposes.
    // Ours rather than the corpus's for the third time and the same
    // reason — the corpus's `List`/`MerkleTree`/`HistoricMerkleTree`
    // declarations are in v2 artifacts, and its v3 ones exercise three of
    // these thirty-one (tests/adts_differential.rs has the scan).
    listed.extend(of("adts", &adts::Adts::CIRCUITS));
    // `kernel.compact` (M17): the kernel primitives and the token-stdlib
    // circuits built on them. Ours rather than the corpus's for the fourth
    // time and the same measured reason — the v3 corpus's kernel/token
    // surface is entirely SHIELDED (tests/kernel_tokens_differential.rs
    // has the scan). `kernel.checkpoint()` is absent because compactc's
    // v3 backend cannot compile it at all.
    listed.extend(of(
        "kernel_tokens",
        &kernel_tokens::KernelTokens::CIRCUITS,
    ));
    // `coins.compact` (M22 stage A): the three COIN ARMS of the collection
    // ADTs — `Set.insertCoin`, `Map.insertCoin`, `List.pushFrontCoin`. Ours
    // rather than the corpus's for the fifth time, and here because the
    // demand is OpenZeppelin's and OZ's artifacts are ZKIR v2
    // (tests/coins_differential.rs has the scan).
    listed.extend(of("coins", &coins::Coins::CIRCUITS));
    // `nested.compact` (M22 stage B1): NESTED ledger ADTs — `Map<K, Map>`,
    // `Map<K, List>`, `Map<K, Set>`, `Map<K, Counter>`, the two trees, and a
    // three-level `Map`. Built at the RAW op layer (`&[LedgerKey]` by hand),
    // because the typed surface is stage B2 and the encoding had to be
    // proven first.
    listed.extend(of("nested", &nested::Nested::CIRCUITS));
    // `manager.compact` (aa-midnight-evm-experiment, pinned in
    // corpus/sources.json): the AA custody contract's nine provable
    // circuits, ported SEMANTICALLY rather than instruction-mirroring —
    // the rows here are deliberately BELOW compactc's artifacts
    // (tests/manager_differential.rs holds the PI-equality warrant).
    listed.extend(of("manager", &manager::Manager::CIRCUITS));
    listed
}

/// A contract's derived circuit set, named `module::circuit` the way the
/// snapshots key their tables.
fn of(module: &str, circuits: &[(&'static str, fn() -> Compiled3)]) -> Vec<Circuit> {
    circuits
        .iter()
        .map(|(name, build)| {
            let name: &'static str = Box::leak(format!("{module}::{name}").into_boxed_str());
            (name, *build)
        })
        .collect()
}

/// Dump a differential test's honest, corpus-verified preimage for the
/// benchmark harness (crates/minocrab-bench): no-op unless
/// `MINOCRAB_DUMP_PREIMAGES=<dir>` is set. Both toolchains' artifacts are
/// PI-equal on these preimages, so the benchmark proves the SAME statement
/// under both.
pub fn dump_preimage(circuit: &str, pi: &ProofPreimage) {
    dump_preimage_in(None, circuit, pi)
}

/// [`dump_preimage`] into a per-side subdirectory. The optimized artifact
/// cannot share the port's preimage — it proves its own statement for the
/// same logical operation — so the benchmark reads its preimages from
/// `preimages/opt/` (crates/minocrab-bench: `Preimages::PerSide`).
pub fn dump_preimage_in(side: Option<&str>, circuit: &str, pi: &ProofPreimage) {
    let Some(dir) = std::env::var_os("MINOCRAB_DUMP_PREIMAGES") else {
        return;
    };
    let mut dir = std::path::PathBuf::from(dir);
    if let Some(side) = side {
        dir.push(side);
    }
    std::fs::create_dir_all(&dir).expect("create preimage dump dir");
    let mut buf = Vec::new();
    midnight_serialize::tagged_serialize(pi, &mut buf).expect("preimage serializes");
    std::fs::write(dir.join(format!("{circuit}.preimage")), buf).expect("preimage writes");
}
