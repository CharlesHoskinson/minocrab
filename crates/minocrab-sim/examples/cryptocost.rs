//! Row costs of the crypto primitives (M10 step 0 instrument), in the
//! spirit of `examples/opcost.rs`: build minimal circuits, difference their
//! cost-model rows, and print what each primitive actually costs.
//!
//! `notes/vault-optimization.org` §"Row-cost model" derives its figures as
//! residuals between snapshot circuits; this example measures them directly
//! and prints the measured-vs-model delta, so the analysis's projections can
//! be re-checked (and the row-attribution constants in
//! `minocrab_sim::v3::rowcost` re-calibrated) at any time.
//!
//! Two numbers per primitive, because the zkir-v3 arch enables a chip only
//! when the circuit uses it (`ir_vm.rs:1212` `used_chips`), so the first use
//! of a primitive also pays for standing up its chip:
//! - *first*: primitive circuit − control circuit (chip stand-up included);
//! - *marginal*: (n+1 uses) − (n uses), the chip already standing.
//!
//! The analysis's per-block/per-op figures are marginal costs, so the
//! measured-vs-model comparison uses the marginal column. Row attribution
//! (`minocrab_sim::v3::rowcost`) is marginal too — the fixed chip cost
//! belongs to no region and shows up as the profile's unattributed residual.
//!
//! The byte-plumbing shapes stay in `examples/opcost.rs`, which already
//! prices `div_mod_power_of_two` against the operand width (147 rows on a
//! 248-bit operand, 101 on 64-bit, 89 on 16-bit) — run that one for those.
//! This example prices `div_mod` only as one line of its
//! everything-else table, to keep `rowcost`'s constants in one place.
//!
//! Run: cargo run --release -p minocrab-sim --example cryptocost
//! (~75s: the padded column re-synthesises a 35k-row circuit per shape).

use minocrab::v3::{
    Bytes32T, Circuit3, FieldT, JubjubPointT, JubjubScalarT, Secp256k1PointT, Secp256k1ScalarT,
    Wire3,
};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Private};
use minocrab_sim::v3::rowcost;
use minocrab_std::v3::{secp256k1_ecdsa_verify, Secp256k1EcdsaSignature, B32};

// --- circuit-building helpers -----------------------------------------------------

fn rows(build: impl FnOnce(&mut Circuit3)) -> usize {
    let mut c = Circuit3::new();
    build(&mut c);
    c.finish(false).ir.model().rows()
}

fn bytes_alignment(len: usize) -> Alignment {
    Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
        length: len as u32,
    })])
}

/// A constrained `Bytes<len>` argument as its FAB limbs (`limbs[0]` is the
/// leftover, most significant chunk — `minocrab_std::v3::BytesNDyn`'s rule,
/// spelled out here because that type is `len > 31` only).
fn bytesn_arg(c: &mut Circuit3, name: &str, len: usize) -> Vec<Wire3<FieldT, Private>> {
    let nlimbs = len.div_ceil(31);
    let leftover = len - 31 * (nlimbs - 1);
    // Every argument must be declared before the first instruction, so
    // declare the whole limb vector, then constrain it.
    let limbs: Vec<Wire3<FieldT, Private>> = (0..nlimbs)
        .map(|i| c.arg(&format!("{name}_{i}")))
        .collect();
    for (i, limb) in limbs.iter().enumerate() {
        let bytes = if i == 0 { leftover } else { 31 };
        c.assert_bits(*limb, 8 * bytes as u32);
    }
    limbs
}

/// `n` copies of `persistent_hash`/`keccak256` over one `Bytes<len>` input
/// (`n = 0` is the control circuit: the input, constrained, unhashed).
fn byte_hash_circuit(len: usize, n: usize, keccak: bool) -> usize {
    rows(|c| {
        let data = bytesn_arg(c, "data", len);
        let inputs: Vec<_> = data.iter().map(|w| w.erase()).collect();
        for _ in 0..n {
            let alignment = bytes_alignment(len);
            let _ = if keccak {
                c.keccak256(alignment, &inputs)
            } else {
                c.persistent_hash(alignment, &inputs)
            };
        }
    })
}

/// `n` copies of `transient_hash` over `limbs` native field elements.
fn poseidon_circuit(limbs: usize, n: usize) -> usize {
    rows(|c| {
        let args: Vec<Wire3<FieldT, Private>> = (0..limbs)
            .map(|i| c.arg::<FieldT>(&format!("x_{i}")))
            .collect();
        for a in &args {
            c.assert_bits(*a, 248);
        }
        for _ in 0..n {
            let _ = c.transient_hash(&args);
        }
    })
}

/// `n` copies of `secp256k1EcdsaVerify(digest, (r, s), pk)`. The public key
/// is a circuit argument in every variant (control included) so the secp256k1
/// chip's arch flag is identical across the row — `used_chips` keys off the
/// input schema, not off `EcMul` (ir_vm.rs:1246-1250).
fn ecdsa_circuit(n: usize) -> usize {
    rows(|c| {
        let pk = c.arg::<Secp256k1PointT>("pk");
        let [digest, r, s] = b32_args(c, ["digest", "r", "s"]);
        for _ in 0..n {
            let sig = ecdsa_sig(c, &r, &s);
            let _ = secp256k1_ecdsa_verify(c, &digest, &sig, pk);
        }
    })
}

/// `(r, s)` as a signature over secp256k1's scalar field.
fn ecdsa_sig(
    c: &mut Circuit3,
    r: &B32<Private>,
    s: &B32<Private>,
) -> Secp256k1EcdsaSignature<Private> {
    let r_typed = r.to_typed(c);
    let s_typed = s.to_typed(c);
    Secp256k1EcdsaSignature {
        r: c.from_bytes32(r_typed),
        s: c.from_bytes32(s_typed),
    }
}

/// `n` constrained `Bytes<32>` arguments — declared first, constrained
/// after (arguments may not follow instructions).
fn b32_args<const N: usize>(c: &mut Circuit3, names: [&str; N]) -> [B32<Private>; N] {
    let args = names.map(|name| B32 {
        hi: c.arg(&format!("{name}_hi")),
        lo: c.arg(&format!("{name}_lo")),
    });
    for b in args {
        b.constrain_input(c);
    }
    args
}

// --- reporting --------------------------------------------------------------------

/// Least-squares fit of `y = slope·x + intercept`; returns the fit and the
/// largest absolute residual.
fn fit(points: &[(f64, f64)]) -> (f64, f64, f64) {
    let n = points.len() as f64;
    let sx: f64 = points.iter().map(|p| p.0).sum();
    let sy: f64 = points.iter().map(|p| p.1).sum();
    let sxx: f64 = points.iter().map(|p| p.0 * p.0).sum();
    let sxy: f64 = points.iter().map(|p| p.0 * p.1).sum();
    let slope = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    let intercept = (sy - slope * sx) / n;
    let residual = points
        .iter()
        .map(|(x, y)| (y - (slope * x + intercept)).abs())
        .fold(0.0f64, f64::max);
    (slope, intercept, residual)
}

struct Headline {
    what: &'static str,
    measured: f64,
    model: f64,
    unit: &'static str,
}

fn deviation_pct(measured: f64, model: f64) -> f64 {
    (measured - model) / model * 100.0
}

fn main() {
    let mut headlines: Vec<Headline> = Vec::new();

    // --- persistent_hash (SHA-256) -----------------------------------------------
    // SHA-256 pads to a whole number of 64-byte blocks with a 1-byte marker
    // and an 8-byte length: blocks = ceil((len + 9) / 64). 55/56 and 119/120
    // straddle the two boundaries the model predicts.
    println!("== persistent_hash (SHA-256) ==");
    println!(
        "{:>6} {:>6} {:>7} {:>9} {:>9} {:>10} {:>10}",
        "bytes", "limbs", "blocks", "control", "1 hash", "first", "marginal"
    );
    let sha_lens = [1usize, 32, 55, 56, 64, 87, 96, 119, 120, 128, 256, 404];
    let mut sha_points: Vec<(f64, f64)> = Vec::new();
    let mut sha_by_len: Vec<(usize, usize)> = Vec::new();
    for len in sha_lens {
        let blocks = (len + 9).div_ceil(64);
        let control = byte_hash_circuit(len, 0, false);
        let one = byte_hash_circuit(len, 1, false);
        let two = byte_hash_circuit(len, 2, false);
        println!(
            "{:>6} {:>6} {:>7} {:>9} {:>9} {:>10} {:>10}",
            len,
            len.div_ceil(31),
            blocks,
            control,
            one,
            one - control,
            two - one,
        );
        sha_points.push((blocks as f64, (two - one) as f64));
        sha_by_len.push((len, two - one));
    }
    let (sha_slope, sha_intercept, sha_resid) = fit(&sha_points);
    println!(
        "fit: marginal = {sha_slope:.1}·blocks + {sha_intercept:.1}  (max residual {sha_resid:.1})"
    );
    println!(
        "blocks = ceil((len+9)/64): confirmed by the 55→56 and 119→120 steps above \
         (per-block cost stays flat, the block count moves).\n"
    );
    let by_len = |table: &[(usize, usize)], len: usize| -> f64 {
        table
            .iter()
            .find(|(l, _)| *l == len)
            .map(|(_, r)| *r as f64)
            .expect("length measured above")
    };
    headlines.push(Headline {
        what: "persistent_hash / 64-byte block",
        measured: sha_slope,
        model: 1_880.0,
        unit: "rows/block",
    });
    // The composites the analysis's per-circuit budget is built from.
    headlines.push(Headline {
        what: "  SHA-256 pair hash (64 B)",
        measured: by_len(&sha_by_len, 64),
        model: 3_760.0,
        unit: "rows",
    });

    // --- keccak256 ----------------------------------------------------------------
    // Keccak-256 absorbs 136-byte blocks with ≥1 byte of padding:
    // blocks = floor(len / 136) + 1. The model carries a per-byte term too,
    // so fit both (blocks, len) → rows by two nested least squares.
    println!("== keccak256 ==");
    println!(
        "{:>6} {:>6} {:>7} {:>9} {:>9} {:>10} {:>10}",
        "bytes", "limbs", "blocks", "control", "1 hash", "first", "marginal"
    );
    let keccak_lens = [1usize, 32, 64, 135, 136, 137, 272, 273, 404, 571];
    let mut keccak_rows: Vec<(usize, usize, f64)> = Vec::new();
    let mut keccak_by_len: Vec<(usize, usize)> = Vec::new();
    for len in keccak_lens {
        let blocks = len / 136 + 1;
        let control = byte_hash_circuit(len, 0, true);
        let one = byte_hash_circuit(len, 1, true);
        let two = byte_hash_circuit(len, 2, true);
        println!(
            "{:>6} {:>6} {:>7} {:>9} {:>9} {:>10} {:>10}",
            len,
            len.div_ceil(31),
            blocks,
            control,
            one,
            one - control,
            two - one,
        );
        keccak_rows.push((blocks, len, (two - one) as f64));
        keccak_by_len.push((len, two - one));
    }
    // Per-byte term: within one block count, rows vary only with len.
    let same_block: Vec<(f64, f64)> = keccak_rows
        .iter()
        .filter(|(b, _, _)| *b == 1)
        .map(|(_, l, r)| (*l as f64, *r))
        .collect();
    let (keccak_per_byte, _, keccak_byte_resid) = fit(&same_block);
    // Per-block term: rows minus the per-byte term, against block count.
    let block_points: Vec<(f64, f64)> = keccak_rows
        .iter()
        .map(|(b, l, r)| (*b as f64, r - keccak_per_byte * *l as f64))
        .collect();
    let (keccak_slope, keccak_intercept, keccak_resid) = fit(&block_points);
    println!(
        "fit: marginal = {keccak_slope:.1}·blocks + {keccak_per_byte:.2}·bytes \
         + {keccak_intercept:.1}  (max residual {keccak_resid:.1}, \
         per-byte fit residual {keccak_byte_resid:.1})"
    );
    println!("blocks = floor(len/136)+1: confirmed by the 135→136→137 steps above.\n");
    headlines.push(Headline {
        what: "keccak256 / 136-byte block",
        measured: keccak_slope,
        model: 4_220.0,
        unit: "rows/block",
    });
    headlines.push(Headline {
        what: "keccak256 / byte",
        measured: keccak_per_byte,
        model: 1.7,
        unit: "rows/byte",
    });
    // The three record shapes the vault hashes (analysis §Row-cost model).
    headlines.push(Headline {
        what: "  attestation digest (32 B, 1 blk)",
        measured: by_len(&keccak_by_len, 32),
        model: 4_280.0,
        unit: "rows",
    });
    headlines.push(Headline {
        what: "  vault event record (404 B)",
        measured: by_len(&keccak_by_len, 404),
        model: 12_900.0,
        unit: "rows",
    });
    headlines.push(Headline {
        what: "  swap event record (571 B)",
        measured: by_len(&keccak_by_len, 571),
        model: 22_070.0,
        unit: "rows",
    });

    // --- secp256k1 ECDSA ----------------------------------------------------------
    println!("== secp256k1EcdsaVerify ==");
    let ecdsa0 = ecdsa_circuit(0);
    let ecdsa1 = ecdsa_circuit(1);
    let ecdsa2 = ecdsa_circuit(2);
    println!("control (args only, secp arch on) rows={ecdsa0}");
    println!("1 verify                          rows={ecdsa1}  (first    {})", ecdsa1 - ecdsa0);
    println!("2 verifies                        rows={ecdsa2}  (marginal {})", ecdsa2 - ecdsa1);
    // The verify's own pieces, marginally (chip already standing). The
    // composites are differenced against each other so each line is one
    // instruction's own cost.
    let ec_mul = ecdsa_part(|c, s, pk| {
        let _ = c.ec_mul(pk, s);
    });
    let ec_mul_gen = ecdsa_part(|c, s, _pk| {
        let _ = c.ec_mul_generator(s);
    });
    let ec_mul_add = ecdsa_part(|c, s, pk| {
        let p = c.ec_mul_generator(s);
        let _ = c.add(p, pk);
    });
    let ec_mul_coord = ecdsa_part(|c, s, pk| {
        let p = c.ec_mul(pk, s);
        let _ = c.into_coordinates(p);
    });
    let ec_mul_coord_bytes = ecdsa_part(|c, s, pk| {
        let p = c.ec_mul(pk, s);
        let (x, _y) = c.into_coordinates(p);
        let _ = c.into_bytes32(x);
    });
    let into_bytes32 = ecdsa_part(|c, s, _pk| {
        let _ = c.into_bytes32(s);
    });
    let bytes32_round_trip = ecdsa_part(|c, s, _pk| {
        let bytes = c.into_bytes32(s);
        let _: Wire3<Secp256k1ScalarT, Private> = c.from_bytes32(bytes);
    });
    let foreign_mul = ecdsa_part(|c, s, _pk| {
        let _ = c.mul(s, s);
    });
    let foreign_inv = ecdsa_part(|c, s, _pk| {
        let _ = c.inv(s);
    });
    let foreign_eq = ecdsa_part(|c, s, _pk| {
        let _ = c.test_eq(s, s);
    });
    let ec_add = ec_mul_add - ec_mul_gen;
    let into_coordinates = ec_mul_coord - ec_mul;
    let into_bytes32_base = ec_mul_coord_bytes - ec_mul_coord;
    let from_bytes32 = bytes32_round_trip - into_bytes32;
    println!("pieces (marginal, secp chip already up):");
    for (label, cost) in [
        ("ec_mul(pk, scalar)", ec_mul),
        ("ec_mul_generator(scalar)", ec_mul_gen),
        ("add(point, point)", ec_add),
        ("into_coordinates(point)", into_coordinates),
        ("into_bytes32(base)", into_bytes32_base),
        ("into_bytes32(scalar)", into_bytes32),
        ("from_bytes32(-> scalar)", from_bytes32),
        ("mul(scalar, scalar)", foreign_mul),
        ("inv(scalar)", foreign_inv),
        ("test_eq(scalar, scalar)", foreign_eq),
    ] {
        println!("  {label:32} {cost:>7}");
    }
    println!(
        "  (2 ec_mul + point add + coordinate/bytes plumbing ≈ {} of the {} \
         measured above)",
        ec_mul + ec_mul_gen + ec_add + into_coordinates + into_bytes32_base,
        ecdsa2 - ecdsa1,
    );
    println!();
    headlines.push(Headline {
        what: "secp256k1EcdsaVerify",
        measured: (ecdsa2 - ecdsa1) as f64,
        model: 25_140.0,
        unit: "rows",
    });

    // --- Jubjub, the native embedded curve ----------------------------------------
    println!("== jubjub (native embedded curve) ==");
    let jj_mul = jubjub_part(|c, p, s, _x| {
        let _ = c.ec_mul(p, s);
    });
    let jj_mul_gen = jubjub_part(|c, _p, s, _x| {
        let _ = c.ec_mul_generator(s);
    });
    let jj_add = jubjub_part(|c, p, s, _x| {
        let q = c.ec_mul_generator(s);
        let _ = c.add(p, q);
    }) - jj_mul_gen;
    let jj_hash_to_curve = jubjub_part(|c, _p, _s, x| {
        let _ = c.hash_to_curve(&[x]);
    });
    let jj_scalar_from_native = jubjub_part(|c, _p, _s, x| {
        let _ = c.jubjub_scalar_from_native(x);
    });
    for (label, cost) in [
        ("ec_mul(point, scalar)", jj_mul),
        ("ec_mul_generator(scalar)", jj_mul_gen),
        ("add(point, point)", jj_add),
        ("hash_to_curve([field])", jj_hash_to_curve),
        ("jubjub_scalar_from_native", jj_scalar_from_native),
    ] {
        println!("  {label:32} {cost:>7}");
    }
    println!();

    // --- transient_hash (Poseidon) ------------------------------------------------
    println!("== transient_hash (Poseidon) ==");
    println!(
        "{:>6} {:>9} {:>9} {:>10} {:>10}",
        "limbs", "control", "1 hash", "first", "marginal"
    );
    let mut poseidon_points: Vec<(f64, f64)> = Vec::new();
    for limbs in [1usize, 2, 3, 4, 6, 8, 12, 16] {
        let control = poseidon_circuit(limbs, 0);
        let one = poseidon_circuit(limbs, 1);
        let two = poseidon_circuit(limbs, 2);
        println!(
            "{:>6} {:>9} {:>9} {:>10} {:>10}",
            limbs,
            control,
            one,
            one - control,
            two - one
        );
        poseidon_points.push((limbs as f64, (two - one) as f64));
    }
    let (pos_slope, pos_intercept, pos_resid) = fit(&poseidon_points);
    let perm_points: Vec<(f64, f64)> = poseidon_points
        .iter()
        .map(|(limbs, r)| ((*limbs as usize).div_ceil(rowcost::POSEIDON_RATE) as f64, *r))
        .collect();
    let (perm_slope, perm_intercept, perm_resid) = fit(&perm_points);
    println!(
        "fit: marginal = {pos_slope:.1}·limbs + {pos_intercept:.1}  \
         (max residual {pos_resid:.1})"
    );
    println!(
        "     = {perm_slope:.1}·permutations + {perm_intercept:.1} at {} limbs per \
         permutation (max residual {perm_resid:.1}) — the sponge's rate is the \
         real unit.\n",
        rowcost::POSEIDON_RATE,
    );
    headlines.push(Headline {
        what: "transient_hash / limb",
        measured: pos_slope,
        model: 15.0,
        unit: "rows/limb",
    });

    // --- div_mod_power_of_two -----------------------------------------------------
    println!("== div_mod_power_of_two ==");
    println!(
        "priced against the OPERAND width by examples/opcost.rs (147 rows on a \
         248-bit operand, 101 on 64-bit, 89 on 16-bit — the analysis's 90-147 \
         band is that example's output). The instruction carries only the split, \
         so `rowcost` prices every div_mod at the full-width figure; one line of \
         the table below re-measures it in this example's frame."
    );
    println!();

    // --- everything else ----------------------------------------------------------
    // Each shape is priced twice — in a minimal circuit and in one padded to
    // ~35k rows — to check whether cost depends on the circuit's k.
    println!("== other instructions (marginal rows) ==");
    println!(
        "{:<38} {:>7} {:>9} {:>7} {:>9}",
        "shape", "k", "marginal", "k", "marginal"
    );
    let mut k_dependent = 0usize;
    for (label, body) in generic_shapes() {
        let (small, k_small) = generic_marginal(false, body);
        let (big, k_big) = generic_marginal(true, body);
        if small.abs_diff(big) * 20 > small.max(big) {
            k_dependent += 1;
        }
        println!("{label:<38} {k_small:>7} {small:>9} {k_big:>7} {big:>9}");
    }
    println!(
        "{k_dependent} shape(s) moved by >5% between the two circuit sizes: cost is \
         flat in k (constrain_bits is 4 bits per row at any size, NOT the \
         ~17 rows per 248 bits at k=16 that notes/vault-optimization.org \
         assumed).\n"
    );

    // --- measured vs model --------------------------------------------------------
    println!("== measured vs notes/vault-optimization.org model ==");
    println!(
        "{:<34} {:>12} {:>12} {:>9}  unit",
        "primitive", "measured", "model", "Δ%"
    );
    let mut flagged = Vec::new();
    for h in &headlines {
        let d = deviation_pct(h.measured, h.model);
        let flag = if d.abs() > 5.0 {
            flagged.push(h.what);
            "  <<< OFF MODEL (>5%)"
        } else {
            ""
        };
        println!(
            "{:<34} {:>12.1} {:>12.1} {:>+8.1}%  {}{}",
            h.what, h.measured, h.model, d, h.unit, flag
        );
    }
    if flagged.is_empty() {
        println!("\nall primitives within 5% of the model: the analysis's projections stand.");
    } else {
        println!(
            "\n*** {} primitive(s) off model by >5%: {} — the projections in \
             notes/vault-optimization.org need revising. ***",
            flagged.len(),
            flagged.join(", ")
        );
    }

    // --- the row-attribution constants --------------------------------------------
    println!("\n== minocrab_sim::v3::rowcost constants (used by --profiles) ==");
    println!(
        "{:<34} {:>12} {:>12} {:>9}",
        "constant", "measured", "rowcost", "Δ%"
    );
    let table: [(&str, f64, f64); 12] = [
        ("SHA256_PER_BLOCK", sha_slope, rowcost::SHA256_PER_BLOCK as f64),
        ("KECCAK_PER_BLOCK", keccak_slope, rowcost::KECCAK_PER_BLOCK as f64),
        ("KECCAK_PER_BYTE", keccak_per_byte, rowcost::KECCAK_PER_BYTE),
        (
            "POSEIDON_PER_PERMUTATION",
            perm_slope,
            rowcost::POSEIDON_PER_PERMUTATION as f64,
        ),
        ("HASH_TO_CURVE", jj_hash_to_curve as f64, rowcost::HASH_TO_CURVE as f64),
        ("EC_MUL_FOREIGN", ec_mul as f64, rowcost::EC_MUL_FOREIGN as f64),
        ("EC_ADD_FOREIGN", ec_add as f64, rowcost::EC_ADD_FOREIGN as f64),
        ("EC_MUL_JUBJUB", jj_mul as f64, rowcost::EC_MUL_JUBJUB as f64),
        (
            "INTO_BYTES32_FOREIGN",
            into_bytes32_base as f64,
            rowcost::INTO_BYTES32_FOREIGN as f64,
        ),
        (
            "FROM_BYTES32_FOREIGN",
            from_bytes32 as f64,
            rowcost::FROM_BYTES32_FOREIGN as f64,
        ),
        ("FOREIGN_MUL", foreign_mul as f64, rowcost::FOREIGN_MUL as f64),
        (
            "whole secp256k1EcdsaVerify",
            (ecdsa2 - ecdsa1) as f64,
            ecdsa_estimate(),
        ),
    ];
    for (name, measured, constant) in table {
        println!(
            "{:<34} {:>12.1} {:>12.1} {:>+8.1}%",
            name,
            measured,
            constant,
            deviation_pct(measured, constant)
        );
    }
}

/// Marginal rows of one extra `body` in a Jubjub frame (point, scalar and a
/// 248-bit native field element).
fn jubjub_part(
    body: impl Fn(
            &mut Circuit3,
            Wire3<JubjubPointT, Private>,
            Wire3<JubjubScalarT, Private>,
            Wire3<FieldT, Private>,
        ) + Copy,
) -> usize {
    let build = |n: usize| {
        rows(|c| {
            let p = c.arg::<JubjubPointT>("p");
            let s = c.arg::<JubjubScalarT>("s");
            let x = c.arg::<FieldT>("x");
            c.assert_bits(x, 248);
            for _ in 0..n {
                body(c, p, s, x);
            }
        })
    };
    build(2) - build(1)
}

/// Pre-declared wires the generic shapes below build on.
struct Frame {
    /// A 248-bit constrained argument.
    wide: Wire3<FieldT, Private>,
    /// An 8-bit constrained argument.
    byte: Wire3<FieldT, Private>,
    /// A constrained `Bytes<32>` argument.
    b32: B32<Private>,
    /// The same value as a typed `Bytes<32>`.
    b32_typed: Wire3<Bytes32T, Private>,
    /// A public constant (impact operands and guards must be public).
    one: Wire3<FieldT, minocrab::Public>,
}

/// Marginal rows of one more `body`, and the k it was measured at. With
/// `pad`, the circuit is first filled to ≈35k rows (k=16, the vault's settle
/// circuits) so range-check-bearing shapes are priced in that regime.
fn generic_marginal(pad: bool, body: fn(&mut Circuit3, &Frame)) -> (usize, u8) {
    let build = |n: usize| -> (usize, u8) {
        let mut c = Circuit3::new();
        let wide = c.arg::<FieldT>("wide");
        let byte = c.arg::<FieldT>("byte");
        let b32 = B32 {
            hi: c.arg("b32_hi"),
            lo: c.arg("b32_lo"),
        };
        c.assert_bits(wide, 248);
        c.assert_bits(byte, 8);
        b32.constrain_input(&mut c);
        let b32_typed = b32.to_typed(&mut c);
        let one = c.constant(1u64);
        if pad {
            // ~21 rows per 2-limb Poseidon permutation.
            for _ in 0..1_600 {
                let _ = c.transient_hash(&[wide, byte]);
            }
        }
        let frame = Frame {
            wide,
            byte,
            b32,
            b32_typed,
            one,
        };
        for _ in 0..n {
            body(&mut c, &frame);
        }
        let model = c.finish(false).ir.model();
        (model.rows(), model.k())
    };
    let (one, _) = build(1);
    let (two, k) = build(2);
    (two - one, k)
}

/// One priced shape: a label and the instructions it builds on a [`Frame`].
type Shape = (&'static str, fn(&mut Circuit3, &Frame));

/// The non-crypto instruction shapes worth pricing: what the vault's
/// framing, byte-plumbing and ledger-op regions are made of.
fn generic_shapes() -> Vec<Shape> {
    vec![
        ("constrain_bits(8)", |c, f| { c.assert_bits(f.byte, 8); }),
        ("constrain_bits(20)", |c, f| { c.assert_bits(f.wide, 20); }),
        ("constrain_bits(64)", |c, f| { c.assert_bits(f.wide, 64); }),
        ("constrain_bits(128)", |c, f| { c.assert_bits(f.wide, 128); }),
        ("constrain_bits(248)", |c, f| { c.assert_bits(f.wide, 248); }),
        ("div_mod_power_of_two(248-bit, 8)", |c, f| {
            let _ = c.div_mod_power_of_two(f.wide, 8);
        }),
        ("div_mod_power_of_two(248-bit, 128)", |c, f| {
            let _ = c.div_mod_power_of_two(f.wide, 128);
        }),
        ("reconstitute_field(_, _, 8)", |c, f| {
            let _ = c.reconstitute_field(f.wide, f.byte, 8);
        }),
        ("less_than(8)", |c, f| {
            let _ = c.less_than(f.byte, f.byte, 8);
        }),
        ("less_than(64)", |c, f| {
            let _ = c.less_than(f.byte, f.byte, 64);
        }),
        ("less_than(248)", |c, f| {
            let _ = c.less_than(f.byte, f.byte, 248);
        }),
        ("add(native)", |c, f| {
            let _ = c.add(f.wide, f.byte);
        }),
        ("mul(native)", |c, f| {
            let _ = c.mul(f.wide, f.byte);
        }),
        ("cond_select(native)", |c, f| {
            let _ = c.cond_select(f.one.private(), f.wide, f.byte);
        }),
        ("test_eq(native)", |c, f| {
            let _ = c.test_eq(f.wide, f.byte);
        }),
        ("not", |c, f| {
            let _ = c.not(f.one);
        }),
        ("assert", |c, f| c.assert(f.one)),
        ("bytes32_from_low_high", |c, f| {
            let _ = c.bytes32_from_low_high(f.b32.lo, f.b32.hi);
        }),
        ("bytes32_into_low_high", |c, f| {
            let _ = c.bytes32_into_low_high(f.b32_typed);
        }),
        ("reverse_bytes", |c, f| {
            let _ = c.reverse_bytes(f.b32_typed);
        }),
        ("into_bytes32(native)", |c, f| {
            let _ = c.into_bytes32(f.wide);
        }),
        ("from_bytes32(-> native)", |c, f| {
            let _: Wire3<FieldT, Private> = c.from_bytes32(f.b32_typed);
        }),
        ("impact(1 elem)", |c, f| c.impact(f.one, &[f.one])),
        ("impact(8 elems)", |c, f| c.impact(f.one, &[f.one; 8])),
        ("public_transcript_input", |c, _f| {
            let _ = c.public_transcript_input::<FieldT>();
        }),
        ("witness", |c, _f| {
            let _ = c.witness::<FieldT>();
        }),
    ]
}

/// Marginal rows of one extra `body` inside the ECDSA argument frame: build
/// the frame with one `body` and with two, and difference.
fn ecdsa_part(
    body: impl Fn(&mut Circuit3, Wire3<Secp256k1ScalarT, Private>, Wire3<Secp256k1PointT, Private>)
        + Copy,
) -> usize {
    let build = |n: usize| {
        rows(|c| {
            let pk = c.arg::<Secp256k1PointT>("pk");
            let [s] = b32_args(c, ["s"]);
            let s_typed = s.to_typed(c);
            let scalar: Wire3<Secp256k1ScalarT, Private> = c.from_bytes32(s_typed);
            for _ in 0..n {
                body(c, scalar, pk);
            }
        })
    };
    build(2) - build(1)
}

/// What `rowcost::est_rows` adds up for one `secp256k1EcdsaVerify` — the
/// instruction mix the eDSL emits (`minocrab_std::v3::secp256k1_ecdsa_verify`).
/// The verify is measured as a REGION of the finished stream: `finish` deletes
/// instructions, so a build-time instruction count cannot index the stream it
/// returns (notes/ir-passes.org §13), and a region is moved onto it.
fn ecdsa_estimate() -> f64 {
    let mut c = Circuit3::new();
    let pk = c.arg::<Secp256k1PointT>("pk");
    let [digest, r, s] = b32_args(&mut c, ["digest", "r", "s"]);
    c.region("ecdsa", |c| {
        let sig = ecdsa_sig(c, &r, &s);
        let _ = secp256k1_ecdsa_verify(c, &digest, &sig, pk);
    });
    let compiled = c.finish(false);
    let verify = compiled
        .regions
        .iter()
        .find(|r| r.label == "ecdsa")
        .expect("the verify was built in its region");
    rowcost::est_rows(&compiled.ir)[verify.start..verify.end]
        .iter()
        .map(|r| *r as f64)
        .sum()
}
