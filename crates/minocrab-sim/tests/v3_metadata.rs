//! Assert messages and regions on random `Circuit3` programs, against an
//! expectation written without the passes (notes/ir-passes.org §13).
//!
//! Each program mixes what `finish` deletes — `assert_with(constant(1))`
//! (a folded copy and a dropped assert), range constraints the opt profile
//! dedups — with what it keeps: asserts on arguments, on other constants,
//! on a constant that is also returned (its copy stays named), and guarded
//! asserts under `when_private`, inside regions nested three deep. Every
//! message must come out on its OWN assert (the argument or immediate it
//! was written on), in order, and every region must hold exactly the
//! messages built inside it and the number of instructions that survive in
//! it. A fixed seed, so a failure reproduces. Before the fix this failed on
//! program 5 (a dropped message kept, at its build-time index).

use minocrab::v3::{Circuit3, Compiled3, FieldT, Wire3};
use minocrab::{Private, Public};
use minocrab_zkir::v3::{Identifier, Instruction, Operand};
use minocrab_zkir::Fr;

/// xorshift64, fixed seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// What a surviving message's assert must read.
#[derive(Clone, Debug)]
enum On {
    /// Argument `k`.
    Arg(usize),
    /// The immediate `v` (a constant the fold inlined).
    Imm(u64),
    /// An assert, whose operand is a name the program cannot predict (a
    /// returned constant's copy, a guarded assert's select).
    Named,
}

struct Program {
    r: Rng,
    args: Vec<Wire3<FieldT, Private>>,
    next_arg: usize,
    /// Every message in build order; `None` for one `finish` must drop.
    messages: Vec<(String, Option<On>)>,
    /// The tightest range proven per argument, for the dedup's expectation.
    bound: Vec<Option<u32>>,
    dedup: bool,
    /// Per region, in the order `Circuit3::region` records them (inner
    /// first): label, messages built inside, surviving instructions if the
    /// program can count them.
    regions: Vec<(String, Vec<usize>, Option<usize>)>,
    outputs: Vec<Wire3<FieldT, Public>>,
    labels: usize,
}

impl Program {
    fn message(&mut self, on: Option<On>, here: &mut Vec<usize>) -> String {
        let m = self.messages.len();
        let text = format!("m{m}");
        self.messages.push((text.clone(), on));
        here.push(m);
        text
    }
}

fn plus(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    Some(a? + b?)
}

/// Emit up to four random steps; return how many instructions survive
/// `finish` from them, when that is known.
fn steps(c: &mut Circuit3, p: &mut Program, depth: u32, here: &mut Vec<usize>) -> Option<usize> {
    let mut survivors = Some(0);
    for _ in 0..p.r.below(5) {
        let n = p.args.len() as u64;
        match p.r.below(if depth < 3 { 8 } else { 7 }) {
            0 if p.next_arg < p.args.len() => {
                let k = p.next_arg;
                p.next_arg += 1;
                let text = p.message(Some(On::Arg(k)), here);
                c.assert_with(p.args[k], Some(&text));
                survivors = plus(survivors, Some(1));
            }
            1 => {
                // `copy %k = 1; assert %k`: both go.
                let one = c.constant(1u64);
                let text = p.message(None, here);
                c.assert_with(one, Some(&text));
            }
            2 => {
                // The copy goes, `assert 7` stays (it can never pass, which
                // is the program's business, not the passes').
                let seven = c.constant(7u64);
                let text = p.message(Some(On::Imm(7)), here);
                c.assert_with(seven, Some(&text));
                survivors = plus(survivors, Some(1));
            }
            3 => {
                // A constant 1 that is also RETURNED: the copy stays named,
                // so the assert reads a name and stays too.
                let one = c.constant(1u64);
                let text = p.message(Some(On::Named), here);
                c.assert_with(one, Some(&text));
                p.outputs.push(one);
                survivors = plus(survivors, Some(2));
            }
            4 | 5 => {
                let j = p.r.below(n) as usize;
                let bits = if p.r.below(2) == 0 {
                    c.assert_boolean(p.args[j]);
                    1
                } else {
                    let bits = [1, 8, 64][p.r.below(3) as usize];
                    c.assert_bits(p.args[j], bits);
                    bits
                };
                let deduped = p.dedup && matches!(p.bound[j], Some(proven) if proven <= bits);
                if !deduped {
                    p.bound[j] = Some(bits);
                }
                survivors = plus(survivors, Some(usize::from(!deduped)));
            }
            6 => {
                let j = p.r.below(n) as usize;
                let (guard, cond) = (p.args[j], p.args[(j + 1) % p.args.len()]);
                let text = p.message(Some(On::Named), here);
                c.when_private(guard, |c| c.assert_with(cond, Some(&text)));
                survivors = None;
            }
            _ => {
                p.labels += 1;
                let label = format!("r{}", p.labels);
                let mut inner = Vec::new();
                let inside = c.region(&label, |c| steps(c, p, depth + 1, &mut inner));
                p.regions.push((label, inner.clone(), inside));
                here.extend(inner);
                survivors = plus(survivors, inside);
            }
        }
    }
    survivors
}

/// The argument names, in order, from the finished circuit's inputs.
fn input_names(compiled: &Compiled3) -> Vec<String> {
    compiled
        .ir
        .inputs
        .iter()
        .map(|t| serde_json::to_value(t).expect("serializes")["name"].as_str().expect("a name").to_string())
        .collect()
}

#[test]
fn random_programs_keep_each_message_on_its_assert_and_each_region_on_its_instructions() {
    let mut seeds = Rng(0x6b65_4316_9f4d_6a6d);
    let (mut total, mut dropped, mut regions, mut emptied, mut deduped_programs) = (0, 0, 0, 0, 0);
    for program in 0..5_000 {
        let seed = seeds.next() | 1;
        let dedup = seeds.below(2) == 0;
        deduped_programs += usize::from(dedup);
        let mut c = Circuit3::new();
        c.dedup_range_constraints(dedup);
        let nargs = 1 + (seed % 6) as usize;
        let args = (0..nargs).map(|k| c.arg::<FieldT>(&format!("a{k}"))).collect();
        let mut p = Program {
            r: Rng(seed),
            args,
            next_arg: 0,
            messages: Vec::new(),
            bound: vec![None; nargs],
            dedup,
            regions: Vec::new(),
            outputs: Vec::new(),
            labels: 0,
        };
        let mut top = Vec::new();
        steps(&mut c, &mut p, 0, &mut top);
        for (k, out) in p.outputs.iter().enumerate() {
            c.output(*out, &format!("o{k}"));
        }
        let compiled = c.finish(false);
        let stream = compiled.ir.instructions.as_slice();
        let names = input_names(&compiled);

        // Messages: exactly the survivors, in build order, each on its own
        // assert, at strictly rising positions.
        let want: Vec<(&str, &On)> = p
            .messages
            .iter()
            .filter_map(|(text, on)| on.as_ref().map(|on| (text.as_str(), on)))
            .collect();
        total += p.messages.len();
        dropped += p.messages.len() - want.len();
        let got: Vec<&str> = compiled.assert_messages.iter().map(|m| m.message.as_str()).collect();
        let texts: Vec<&str> = want.iter().map(|(text, _)| *text).collect();
        assert_eq!(got, texts, "program {program}: the surviving messages");
        for pair in compiled.assert_messages.windows(2) {
            assert!(pair[0].instruction < pair[1].instruction, "program {program}: order");
        }
        for (m, (_, on)) in compiled.assert_messages.iter().zip(&want) {
            let Some(Instruction::Assert { cond }) = stream.get(m.instruction) else {
                panic!("program {program}: {m:?} is not on an assert");
            };
            match on {
                On::Arg(k) => assert_eq!(
                    cond,
                    &Operand::Variable(Identifier(names[*k].clone())),
                    "program {program}: {m:?}"
                ),
                On::Imm(v) => assert_eq!(cond, &Operand::Immediate(Fr::from(*v)), "program {program}: {m:?}"),
                On::Named => assert!(matches!(cond, Operand::Variable(_)), "program {program}: {m:?}"),
            }
            assert_eq!(compiled.assert_message(m.instruction), Some(m.message.as_str()));
        }

        // Regions: each holds exactly the surviving messages built inside
        // it, and the instructions that survive in it; none cross.
        assert_eq!(compiled.regions.len(), p.regions.len());
        for (region, (label, inner, inside)) in compiled.regions.iter().zip(&p.regions) {
            regions += 1;
            assert_eq!(&region.label, label);
            assert!(region.start <= region.end && region.end <= stream.len(), "program {program}: {region:?}");
            emptied += usize::from(region.start == region.end);
            if let Some(inside) = inside {
                assert_eq!(region.end - region.start, *inside, "program {program}: {region:?}");
            }
            let mut held: Vec<&str> = compiled
                .assert_messages
                .iter()
                .filter(|m| (region.start..region.end).contains(&m.instruction))
                .map(|m| m.message.as_str())
                .collect();
            let mut built: Vec<&str> = inner
                .iter()
                .filter_map(|&m| p.messages[m].1.as_ref().map(|_| p.messages[m].0.as_str()))
                .collect();
            held.sort_unstable();
            built.sort_unstable();
            assert_eq!(held, built, "program {program}: region {label}");
        }
        for (i, a) in compiled.regions.iter().enumerate() {
            for b in &compiled.regions[i + 1..] {
                let disjoint = a.end <= b.start || b.end <= a.start;
                let nested = (a.start <= b.start && b.end <= a.end) || (b.start <= a.start && a.end <= b.end);
                assert!(disjoint || nested, "program {program}: {a:?} crosses {b:?}");
            }
        }
    }
    // The programs exercise the drops, the emptied regions and the dedup.
    assert!(dropped > 500 && emptied > 100 && deduped_programs > 1000, "{total} {dropped} {regions} {emptied}");
}
