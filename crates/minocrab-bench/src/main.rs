//! M6 baseline benchmark harness: the erc20-vault contract (twenty-nine
//! circuits since M44) and its Signet singleton dependency, proved under
//! each toolchain at the same pinned versions.
//!
//! A run is a matrix of circuits ([`Target`]) × [`Side`]s, and sides are
//! data: a name, where its circuits come from ([`Artifacts`]) and where its
//! `ProofPreimage`s come from ([`Preimages`]). Two are declared:
//! - `minocrab` — the direct ports, built in-process from `minocrab-contracts`;
//! - `compactc` — the corpus `.zkir` goldens.
//!
//! `minocrab` and `compactc` prove the SAME preimage per circuit: the
//! differential tests establish PI-equality on these preimages and (with
//! `MINOCRAB_DUMP_PREIMAGES`) dump them for this harness, so those numbers
//! price the identical statement. (The M10/M11 `opt` and `borsh` sides,
//! which proved their own preimages, were retired with their forks in M28 —
//! notes/vault-refresh.org §0; `Preimages::PerSide` is kept for the next
//! side that cannot share a statement.)
//!
//! Run via `./bench.sh` (dumps preimages, then runs this binary in release
//! mode). Modes:
//! - no args: orchestrate — spawn `--measure` subprocesses (one per
//!   circuit × side, so peak RSS is per-measurement), collect JSON, write
//!   `target/bench/results.json` + `target/bench/report.md`, and dump
//!   the eDSL sides' per-region cost profiles.
//! - `--measure <circuit> <side>`: keygen + prove + verify one artifact,
//!   print a JSON result line. RAM is `getrusage` peak RSS.
//! - `--profiles`: rewrite `target/bench/profiles/` alone (no proving) —
//!   for refreshing region attribution after annotation changes.
//! - `--list`: print the circuit × side matrix this run would measure, with
//!   each cell's artifact and preimage source. A dry run; proves nothing.

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use midnight_transient_crypto::proofs::{ParamsProverProvider, ProofPreimage, Zkir};
use minocrab_contracts::{erc20_vault, signet_contract};
use minocrab_zkir::v3::IrSource;
use serde::{Deserialize, Serialize};

struct Target {
    /// Circuit name — also the corpus `.zkir` and dumped `.preimage` stem.
    name: &'static str,
    /// Corpus artifact path relative to the repo root.
    corpus: &'static str,
    /// The MinoCrab direct port.
    ours: fn() -> minocrab::v3::Compiled3,
}

/// Where a side's circuits come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Artifacts {
    /// Built in-process from `minocrab-contracts`' direct ports.
    Port,
    /// compactc's `.zkir` goldens in `corpus/`.
    Corpus,
}

/// Where a side's [`ProofPreimage`]s come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Preimages {
    /// The preimages the differential tests dump: compactc and the direct
    /// port are PI-equal on these, so both sides price the identical
    /// statement.
    Shared,
    /// A per-side subdirectory, for a side that cannot share the port's
    /// preimage because it proves its *own* statement for the same logical
    /// operation (the retired `opt` side was one; the methodology caveat is
    /// notes/vault-optimization.org §Sequencing). No declared side uses it
    /// today.
    #[allow(dead_code)]
    PerSide(&'static str),
}

/// One column of the benchmark.
struct Side {
    /// Name on the command line, in `results.json` and in the report.
    name: &'static str,
    artifacts: Artifacts,
    preimages: Preimages,
}

fn sides() -> Vec<Side> {
    vec![
        Side {
            name: "minocrab",
            artifacts: Artifacts::Port,
            preimages: Preimages::Shared,
        },
        Side {
            name: "compactc",
            artifacts: Artifacts::Corpus,
            preimages: Preimages::Shared,
        },
    ]
}

fn side(name: &str) -> Result<Side> {
    sides()
        .into_iter()
        .find(|s| s.name == name)
        .with_context(|| {
            format!(
                "unknown side {name}; known: {}",
                sides()
                    .iter()
                    .map(|s| s.name)
                    .collect::<Vec<_>>()
                    .join("|")
            )
        })
}

impl Side {
    /// The circuits this side contributes for `target`, or `None` when it
    /// has no artifact for it (an absent side simply drops out of the run).
    fn ir(&self, target: &Target) -> Option<Result<IrSource>> {
        match self.artifacts {
            Artifacts::Port => Some(Ok((target.ours)().ir)),
            Artifacts::Corpus => {
                let path = repo_root().join(target.corpus);
                Some(
                    minocrab_zkir::v3::read_zkir(path.to_str().unwrap())
                        .with_context(|| format!("corpus artifact {}", target.corpus)),
                )
            }
        }
    }

    /// Profiles are MinoCrab-side only: they need the eDSL's region
    /// annotations, which a parsed `.zkir` does not carry.
    fn profiled(&self, target: &Target) -> Option<minocrab::v3::Compiled3> {
        match self.artifacts {
            Artifacts::Port => Some((target.ours)()),
            Artifacts::Corpus => None,
        }
    }

    fn preimage_path(&self, circuit: &str) -> PathBuf {
        match self.preimages {
            Preimages::Shared => preimage_dir().join(format!("{circuit}.preimage")),
            Preimages::PerSide(dir) => preimage_dir().join(dir).join(format!("{circuit}.preimage")),
        }
    }
}

const VAULT: &str =
    "corpus/zkir/signet-midnight-examples/examples/erc20-vault/contract/src/erc20-vault/zkir";
const SIGNET: &str =
    "corpus/zkir/signet-midnight-integration-pr127/packages/signet-contract/src/signet-contract/zkir";

fn targets() -> Vec<Target> {
    macro_rules! t {
        ($dir:expr, $name:literal, $f:expr) => {
            Target {
                name: $name,
                corpus: constcat($dir, $name),
                ours: $f,
            }
        };
    }
    fn constcat(dir: &str, name: &str) -> &'static str {
        Box::leak(format!("{dir}/{name}.zkir").into_boxed_str())
    }
    vec![
        t!(VAULT, "initialise", || erc20_vault::Vault::initialise()),
        t!(VAULT, "setGasParams", || erc20_vault::Vault::set_gas_params()),
        t!(VAULT, "addAllowedToken", || erc20_vault::Vault::add_allowed_token()),
        t!(VAULT, "flushQueue", || erc20_vault::Vault::flush_queue()),
        t!(VAULT, "queueAttestation0", || erc20_vault::Vault::queue_attestation0()),
        t!(VAULT, "queueAttestation1", || erc20_vault::Vault::queue_attestation1()),
        t!(VAULT, "queueAttestation32", || erc20_vault::Vault::queue_attestation32()),
        t!(VAULT, "startReplaceNonce", || erc20_vault::Vault::start_replace_nonce()),
        t!(VAULT, "sendReplaceNonce", || erc20_vault::Vault::send_replace_nonce()),
        t!(VAULT, "completeReplaceNonce", || erc20_vault::Vault::complete_replace_nonce()),
        t!(VAULT, "startApproveRouter", || erc20_vault::Vault::start_approve_router()),
        t!(VAULT, "startApproveStata", || erc20_vault::Vault::start_approve_stata()),
        t!(VAULT, "sendApprove", || erc20_vault::Vault::send_approve()),
        t!(VAULT, "completeApprove", || erc20_vault::Vault::complete_approve()),
        t!(VAULT, "startDeposit", || erc20_vault::Vault::start_deposit()),
        t!(VAULT, "sendDeposit", || erc20_vault::Vault::send_deposit()),
        t!(VAULT, "completeDeposit", || erc20_vault::Vault::complete_deposit()),
        t!(VAULT, "startWithdraw", || erc20_vault::Vault::start_withdraw()),
        t!(VAULT, "sendWithdraw", || erc20_vault::Vault::send_withdraw()),
        t!(VAULT, "completeWithdraw", || erc20_vault::Vault::complete_withdraw()),
        t!(VAULT, "startSwap", || erc20_vault::Vault::start_swap()),
        t!(VAULT, "sendSwap", || erc20_vault::Vault::send_swap()),
        t!(VAULT, "completeSwap", || erc20_vault::Vault::complete_swap()),
        t!(VAULT, "startSupply", || erc20_vault::Vault::start_supply()),
        t!(VAULT, "sendSupply", || erc20_vault::Vault::send_supply()),
        t!(VAULT, "completeSupply", || erc20_vault::Vault::complete_supply()),
        t!(VAULT, "startRedeem", || erc20_vault::Vault::start_redeem()),
        t!(VAULT, "sendRedeem", || erc20_vault::Vault::send_redeem()),
        t!(VAULT, "completeRedeem", || erc20_vault::Vault::complete_redeem()),
        t!(SIGNET, "signBidirectional", || signet_contract::SignetContract::sign_bidirectional()),
        t!(SIGNET, "respond", || signet_contract::SignetContract::respond()),
        t!(SIGNET, "respondBidirectional", || signet_contract::SignetContract::respond_bidirectional()),
    ]
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn bench_dir() -> PathBuf {
    repo_root().join("target/bench")
}

fn preimage_dir() -> PathBuf {
    std::env::var_os("MINOCRAB_PREIMAGES")
        .map(PathBuf::from)
        .unwrap_or_else(|| bench_dir().join("preimages"))
}

fn load_preimage(side: &Side, name: &str) -> Result<ProofPreimage> {
    let path = side.preimage_path(name);
    let bytes = std::fs::read(&path).with_context(|| {
        format!(
            "no dumped preimage at {} — run the differential tests with \
             MINOCRAB_DUMP_PREIMAGES set (see bench.sh)",
            path.display()
        )
    })?;
    Ok(midnight_serialize::tagged_deserialize(&bytes[..])?)
}

fn load_ir(target: &Target, side: &Side) -> Result<IrSource> {
    side.ir(target).unwrap_or_else(|| {
        bail!(
            "side {} has no artifact for circuit {}",
            side.name,
            target.name
        )
    })
}

fn params_provider() -> Result<MidnightDataProvider> {
    Ok(MidnightDataProvider::new(
        FetchMode::OnDemand,
        OutputMode::Log,
        vec![],
    )?)
}

/// Peak RSS of this process, in bytes.
fn peak_rss_bytes() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    assert_eq!(rc, 0, "getrusage failed");
    let raw = ru.ru_maxrss as u64;
    // macOS reports bytes, Linux kilobytes.
    if cfg!(target_os = "macos") {
        raw
    } else {
        raw * 1024
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Measurement {
    circuit: String,
    side: String,
    k: u8,
    rows: usize,
    keygen_s: f64,
    prove_s: f64,
    verify_s: f64,
    proof_bytes: usize,
    peak_rss_bytes: u64,
}

async fn measure(name: &str, side_name: &str) -> Result<Measurement> {
    let target_list = targets();
    let target = target_list
        .iter()
        .find(|t| t.name == name)
        .with_context(|| format!("unknown circuit {name}"))?;
    let side = side(side_name)?;

    let ir = load_ir(target, &side)?;
    let pi = load_preimage(&side, name)?;
    let params = params_provider()?;

    let model = ir.model();
    let (k, rows) = (model.k(), model.rows());

    // Warm the params cache so a first-run download never lands in the
    // keygen timing. (keygen/prove re-read the cached file; both sides pay
    // that I/O equally.)
    params.get_params(k).await?;

    let t = Instant::now();
    let (pk, vk) = ir.keygen(&params).await?;
    let keygen_s = t.elapsed().as_secs_f64();

    // Median of N proves (MINOCRAB_PROVE_ITERS, default 3): single-shot
    // wall-clock proved to swing ~3× with machine state.
    let iters: usize = std::env::var("MINOCRAB_PROVE_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let mut times = Vec::with_capacity(iters);
    let mut last = None;
    for _ in 0..iters {
        let t = Instant::now();
        let (proof, pis, _skips) = ir
            .prove(rand::rngs::OsRng, &params, pk.clone(), &pi)
            .await
            .map_err(|e| anyhow::anyhow!("prove: {e}"))?;
        times.push(t.elapsed().as_secs_f64());
        last = Some((proof, pis));
    }
    times.sort_by(f64::total_cmp);
    let prove_s = times[times.len() / 2];
    let (proof, pis) = last.expect("at least one prove iteration");
    let proof_bytes = proof.0.len();

    // `ParamsProver::as_verifier` is pub(crate); read the verifier params
    // from the provider's cached file instead (same dir resolution).
    let params_file = std::env::var_os("MIDNIGHT_PP")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("XDG_CACHE_HOME")
                .map(|p| PathBuf::from(p).join("midnight/zk-params"))
        })
        .or_else(|| {
            std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".cache/midnight/zk-params"))
        })
        .context("no cache dir")?
        .join(format!("bls_midnight_2p{k}"));
    let verifier_params = midnight_transient_crypto::proofs::ParamsVerifier::read(
        std::io::BufReader::new(std::fs::File::open(&params_file)?),
    )?;
    let t = Instant::now();
    vk.verify(&verifier_params, &proof, pis.iter().copied())
        .map_err(|e| anyhow::anyhow!("verify: {e}"))?;
    let verify_s = t.elapsed().as_secs_f64();

    Ok(Measurement {
        circuit: name.to_string(),
        side: side.name.to_string(),
        k,
        rows,
        keygen_s,
        prove_s,
        verify_s,
        proof_bytes,
        peak_rss_bytes: peak_rss_bytes(),
    })
}

fn orchestrate() -> Result<()> {
    let out_dir = bench_dir();
    std::fs::create_dir_all(&out_dir)?;
    let exe = std::env::current_exe()?;

    // Incremental: one JSON line per finished cell; a restarted run skips
    // what's already measured. Delete results.jsonl for a fresh run.
    let jsonl_path = out_dir.join("results.jsonl");
    let mut results: Vec<Measurement> = match std::fs::read_to_string(&jsonl_path) {
        Ok(s) => s
            .lines()
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?,
        Err(_) => Vec::new(),
    };

    for (target, side) in cells() {
        {
            let side = side.name;
            if results
                .iter()
                .any(|m| m.circuit == target.name && m.side == side)
            {
                continue;
            }
            eprint!("{:>20} {:>8} … ", target.name, side);
            std::io::stderr().flush().ok();
            let t = Instant::now();
            let output = std::process::Command::new(&exe)
                .args(["--measure", target.name, side])
                .output()?;
            if !output.status.success() {
                bail!(
                    "--measure {} {} failed:\n{}",
                    target.name,
                    side,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let line = String::from_utf8(output.stdout)?;
            let m: Measurement = serde_json::from_str(
                line.lines().last().context("no measurement output")?,
            )?;
            eprintln!(
                "k={} prove {:.2}s rss {:.0}MB  ({:.0}s total)",
                m.k,
                m.prove_s,
                m.peak_rss_bytes as f64 / 1e6,
                t.elapsed().as_secs_f64()
            );
            let mut jsonl = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&jsonl_path)?;
            writeln!(jsonl, "{}", serde_json::to_string(&m)?)?;
            results.push(m);
        }
    }

    // Report in target × side order regardless of when each cell was measured.
    let order: Vec<&str> = targets().iter().map(|t| t.name).collect();
    let side_order: Vec<&str> = sides().iter().map(|s| s.name).collect();
    results.sort_by_key(|m| {
        (
            order.iter().position(|n| *n == m.circuit),
            side_order.iter().position(|n| *n == m.side),
        )
    });

    serde_json::to_writer_pretty(
        std::fs::File::create(out_dir.join("results.json"))?,
        &results,
    )?;

    write_profiles(&out_dir)?;

    let report = render_report(&results);
    std::fs::write(out_dir.join("report.md"), &report)?;
    println!("{report}");
    eprintln!(
        "written: {}/results.json, report.md, profiles/",
        out_dir.display()
    );
    Ok(())
}

/// Every (circuit, side) pair the run covers — a side without an artifact
/// for a circuit drops out rather than failing the run.
fn cells() -> Vec<(Target, Side)> {
    let mut out = Vec::new();
    for target in targets() {
        for side in sides() {
            if side.ir(&target).is_some() {
                out.push((
                    Target {
                        name: target.name,
                        corpus: target.corpus,
                        ours: target.ours,
                    },
                    side,
                ));
            }
        }
    }
    out
}

/// Per-region cost profiles (the M7 target-picker, now attributed by
/// estimated rows as well as instruction count). Built in-process from the
/// eDSL circuits — no proving, so `--profiles` can refresh them alone after
/// a region-annotation change. compactc's parsed `.zkir` carries no regions,
/// so only the eDSL sides are profiled; a side's files are suffixed with its
/// name (the port keeps the bare `<circuit>.txt` names).
fn write_profiles(out_dir: &std::path::Path) -> Result<()> {
    let profile_dir = out_dir.join("profiles");
    std::fs::create_dir_all(&profile_dir)?;
    for (target, side) in cells() {
        let Some(compiled) = side.profiled(&target) else {
            continue;
        };
        let stem = match side.artifacts {
            Artifacts::Port => target.name.to_string(),
            _ => format!("{}.{}", target.name, side.name),
        };
        let profile = minocrab_sim::v3::profile(&compiled);
        std::fs::write(profile_dir.join(format!("{stem}.txt")), format!("{profile}"))?;
        serde_json::to_writer_pretty(
            std::fs::File::create(profile_dir.join(format!("{stem}.json")))?,
            &profile,
        )?;
    }
    Ok(())
}

/// `--list`: the (circuit, side) matrix this run would measure, with each
/// cell's artifact and preimage source. A dry run — nothing is built or
/// proved beyond reading what is on disk.
fn list_cells() -> Result<()> {
    /// The last two path components, enough to tell the cells apart.
    fn tail(path: &std::path::Path) -> String {
        let parts: Vec<_> = path.components().rev().take(2).collect();
        let tail: PathBuf = parts.into_iter().rev().collect();
        format!("…/{}", tail.display())
    }
    println!("{:>20} {:>10}  {:<28} preimage", "circuit", "side", "artifact");
    for (target, side) in cells() {
        let artifact = match side.artifacts {
            Artifacts::Port => "minocrab-contracts (port)".to_string(),
            Artifacts::Corpus => tail(std::path::Path::new(target.corpus)),
        };
        let preimage = side.preimage_path(target.name);
        let present = if preimage.exists() { "" } else { "  [missing]" };
        println!(
            "{:>20} {:>10}  {:<28} {}{}",
            target.name,
            side.name,
            artifact,
            tail(&preimage),
            present
        );
    }
    let absent: Vec<&str> = sides()
        .iter()
        .filter(|s| !cells().iter().any(|(_, c)| c.name == s.name))
        .map(|s| s.name)
        .collect();
    if !absent.is_empty() {
        println!("\nsides with no artifacts yet (skipped): {}", absent.join(", "));
    }
    Ok(())
}

fn render_report(results: &[Measurement]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    writeln!(s, "# MinoCrab vs compactc (same preimage per circuit)\n").unwrap();
    writeln!(
        s,
        "| circuit | side | k | rows | keygen (s) | prove (s) | verify (s) | proof (B) | peak RSS (MB) |"
    )
    .unwrap();
    writeln!(s, "|---|---|---|---|---|---|---|---|---|").unwrap();
    for m in results {
        writeln!(
            s,
            "| {} | {} | {} | {} | {:.2} | {:.2} | {:.3} | {} | {:.0} |",
            m.circuit,
            m.side,
            m.k,
            m.rows,
            m.keygen_s,
            m.prove_s,
            m.verify_s,
            m.proof_bytes,
            m.peak_rss_bytes as f64 / 1e6,
        )
        .unwrap();
    }
    // Deltas of every other side against compactc, the common baseline.
    let by = |c: &str, side: &str| results.iter().find(|m| m.circuit == c && m.side == side);
    let mut names: Vec<&str> = results.iter().map(|m| m.circuit.as_str()).collect();
    names.dedup();
    for side in sides() {
        if side.artifacts == Artifacts::Corpus {
            continue;
        }
        if !results.iter().any(|m| m.side == side.name) {
            continue;
        }
        writeln!(s, "\n## Deltas ({} vs compactc)\n", side.name).unwrap();
        if let Preimages::PerSide(_) = side.preimages {
            writeln!(
                s,
                "This side proves its OWN preimage per circuit — the same logical \
                 operation, not the same statement. Comparability rests on the \
                 symbolic-effect equality of the two contracts, a weaker claim than \
                 the PI-equality the other sides share.\n"
            )
            .unwrap();
        }
        writeln!(s, "| circuit | rows Δ | prove Δ | RSS Δ |").unwrap();
        writeln!(s, "|---|---|---|---|").unwrap();
        for name in &names {
            if let (Some(a), Some(b)) = (by(name, side.name), by(name, "compactc")) {
                let pct = |x: f64, y: f64| if y != 0.0 { (x - y) / y * 100.0 } else { 0.0 };
                writeln!(
                    s,
                    "| {} | {:+.1}% | {:+.1}% | {:+.1}% |",
                    name,
                    pct(a.rows as f64, b.rows as f64),
                    pct(a.prove_s, b.prove_s),
                    pct(a.peak_rss_bytes as f64, b.peak_rss_bytes as f64),
                )
                .unwrap();
            }
        }
    }
    s
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        None => orchestrate(),
        Some("--measure") => {
            let name = args.get(2).context("--measure <circuit> <side>")?;
            let side = args.get(3).context("--measure <circuit> <side>")?;
            let m = measure(name, side).await?;
            println!("{}", serde_json::to_string(&m)?);
            Ok(())
        }
        Some("--profiles") => {
            let out_dir = bench_dir();
            write_profiles(&out_dir)?;
            eprintln!("written: {}/profiles/", out_dir.display());
            Ok(())
        }
        Some("--list") => list_cells(),
        Some(other) => bail!("unknown mode {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every side has an artifact for every target, so the matrix is the
    /// full product; asking a side for a target it lacks is an error, not a
    /// panic.
    #[test]
    fn every_target_is_two_sided() {
        assert_eq!(
            targets().len(),
            32,
            "twenty-nine vault circuits and the singleton's three"
        );
        assert_eq!(cells().len(), targets().len() * 2);
        let signet = targets().into_iter().find(|t| t.name == "respond").unwrap();
        assert!(load_ir(&signet, &side("compactc").unwrap()).is_ok());
    }

    #[test]
    fn unknown_side_is_rejected() {
        assert!(side("nonesuch").is_err());
        assert!(side("minocrab").is_ok());
        assert!(side("compactc").is_ok());
    }

    /// The two statement-identical sides read the shared preimage dump.
    #[test]
    fn preimages_are_shared() {
        let shared = side("minocrab").unwrap().preimage_path("completeDeposit");
        assert_eq!(shared, side("compactc").unwrap().preimage_path("completeDeposit"));
    }

    /// Both toolchain-independent sides yield an IR for every target, and
    /// only the eDSL ones can be profiled.
    #[test]
    fn every_target_has_a_port_and_a_corpus_artifact() {
        for target in targets() {
            for name in ["minocrab", "compactc"] {
                let side = side(name).unwrap();
                assert!(
                    side.ir(&target).expect("side present").is_ok(),
                    "{} / {name}",
                    target.name
                );
            }
            assert!(side("minocrab").unwrap().profiled(&target).is_some());
            assert!(side("compactc").unwrap().profiled(&target).is_none());
        }
    }
}
