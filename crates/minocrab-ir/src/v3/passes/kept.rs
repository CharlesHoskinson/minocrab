//! `Kept`: where each instruction of a stream went through the passes that
//! `Builder3::finish` runs, and `retain_kept`, the one way those passes build
//! it (notes/ir-passes.org §13).
//!
//! INTERNAL TIER. The module is private; `Kept` is re-exported from
//! `passes` only under the `unstable` feature, for `Builder3::finish_kept`
//! and the `minocrab` frontend. It bakes in "every pass in `finish` is a
//! filter", which is a fact about today's `finish`, not a promise the stable
//! tier makes.

use minocrab_zkir::v3::Instruction;

/// Where each instruction of a stream went through a run of passes that only
/// ever DELETE — the map that carries a BUILD-TIME instruction index (an
/// `AssertMessage`, a region's `[start, end)`, in `minocrab::v3`) onto the
/// stream that ships.
///
/// Every pass `Builder3::finish` runs is a filter: its output is a
/// subsequence of its input, in the same order, with operands rewritten at
/// most (the Lean models prove it of the algorithms: `dedup_sublist`,
/// `dropTrueAsserts_sublist`, `fold_is_filter_map`). So one bit per input
/// instruction — kept or dropped — determines the whole map. Each pass gets
/// its map from `retain_kept`, which records that bit as the value of the
/// pass's own keep decision, so the map and the stream cannot disagree.
///
/// Stored as the running count of kept instructions: `before[i]` is how many
/// of the first `i` input instructions survived, so `before` has one more
/// entry than the input and `before[n]` is the output's length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    before: Vec<usize>,
}

// Read only by `Builder3::finish_kept` and the `minocrab` frontend, both
// behind `unstable`; the stable tier builds the map and drops it.
#[cfg_attr(not(feature = "unstable"), allow(dead_code))]
impl Kept {
    /// The map of a pass that dropped nothing from a stream of `len`
    /// instructions.
    pub(crate) fn identity(len: usize) -> Self {
        Kept {
            before: (0..=len).collect(),
        }
    }

    /// Instructions in the input stream.
    pub fn input_len(&self) -> usize {
        self.before.len() - 1
    }

    /// Instructions in the output stream.
    pub fn output_len(&self) -> usize {
        self.before[self.input_len()]
    }

    /// Where input instruction `index` landed, or `None` if a pass dropped
    /// it. `None` means dropped and nothing else: an index past the input is
    /// a caller's bug, and panics rather than reading as a deletion.
    ///
    /// # Panics
    ///
    /// If `index >= self.input_len()`.
    pub fn position(&self, index: usize) -> Option<usize> {
        assert!(
            index < self.input_len(),
            "Kept::position: instruction {index} is not in the {}-instruction stream this map \
             was built over; take the index from the same Builder3, before finish",
            self.input_len()
        );
        (self.before[index + 1] > self.before[index]).then_some(self.before[index])
    }

    /// Where the BOUNDARY in front of input instruction `index` landed — the
    /// map for a half-open `[start, end)`: the output span `[boundary(start),
    /// boundary(end))` holds exactly the survivors of the input span, in
    /// order, and is empty when none survived. `index` may be the input's
    /// length (the end of the stream).
    ///
    /// # Panics
    ///
    /// If `index > self.input_len()`.
    pub fn boundary(&self, index: usize) -> usize {
        assert!(
            index <= self.input_len(),
            "Kept::boundary: boundary {index} is past the end of the {}-instruction stream this \
             map was built over; take the index from the same Builder3, before finish",
            self.input_len()
        );
        self.before[index]
    }

    /// This map followed by `later`, which ran over this map's output.
    ///
    /// # Panics
    ///
    /// If `later` was not built over this map's output (the lengths differ).
    /// `Builder3::finish_kept` is the one caller and composes the passes in
    /// the order it runs them, so this is an internal invariant.
    pub(crate) fn compose(&self, later: &Kept) -> Kept {
        assert_eq!(
            self.output_len(),
            later.input_len(),
            "Kept::compose: compose the maps in pass order, each over the previous pass's output"
        );
        Kept {
            before: self.before.iter().map(|&b| later.before[b]).collect(),
        }
    }
}

/// The one way a pass in `Builder3::finish` deletes instructions: keep each
/// instruction for which `keep` returns true, visiting them in order, once
/// each (`Vec::retain_mut`), and record that same return value as the
/// instruction's bit in the [`Kept`] map. `keep` may rewrite the
/// instruction's operands before it decides; it cannot insert or reorder.
pub(crate) fn retain_kept(
    mut instructions: Vec<Instruction>,
    mut keep: impl FnMut(&mut Instruction) -> bool,
) -> (Vec<Instruction>, Kept) {
    let mut before = Vec::with_capacity(instructions.len() + 1);
    let mut survivors = 0;
    before.push(survivors);
    instructions.retain_mut(|instruction| {
        let kept = keep(instruction);
        survivors += usize::from(kept);
        before.push(survivors);
        kept
    });
    (instructions, Kept { before })
}

#[cfg(test)]
mod tests {
    //! Each pass's map against the stream it describes, on fixed and on
    //! random streams (a fixed seed, so a failure reproduces), and the
    //! composition `Builder3::finish_kept` relies on.

    use super::{retain_kept, Kept};
    use crate::v3::passes::{
        dedup_range_constraints, dedup_range_constraints_kept, drop_true_asserts,
        drop_true_asserts_kept, fold_immediate_copies, fold_immediate_copies_kept,
    };
    use minocrab_zkir::v3::{Identifier, Instruction, Operand};
    use minocrab_zkir::Fr;

    fn var(name: &str) -> Operand {
        Operand::Variable(Identifier(name.to_string()))
    }

    fn imm(v: u64) -> Operand {
        Operand::Immediate(Fr::from(v))
    }

    fn assert_on(cond: Operand) -> Instruction {
        Instruction::Assert { cond }
    }

    fn copy(val: Operand, output: &str) -> Instruction {
        Instruction::Copy {
            val,
            output: Identifier(output.to_string()),
        }
    }

    fn bits(name: &str, bits: u32) -> Instruction {
        Instruction::ConstrainBits { val: var(name), bits }
    }

    fn boolean(name: &str) -> Instruction {
        Instruction::ConstrainToBoolean { val: var(name) }
    }

    /// The map's law against an INDEPENDENT expectation: `survivors[i]` is
    /// what input `i` must have become in the output (`None`: dropped). Every
    /// survivor lands where `position` says, in order, `position` is `None`
    /// for exactly the dropped ones, and every boundary counts the survivors
    /// in front of it. Comparing whole instructions, operands included, is
    /// what catches two asserts trading places.
    fn check(kept: &Kept, output: &[Instruction], survivors: &[Option<Instruction>]) {
        assert_eq!(kept.input_len(), survivors.len());
        assert_eq!(kept.output_len(), output.len());
        let mut next = 0;
        for (index, survivor) in survivors.iter().enumerate() {
            assert_eq!(kept.boundary(index), next, "boundary before {index}");
            assert_eq!(kept.position(index).is_some(), survivor.is_some(), "{index}");
            if let Some(want) = survivor {
                assert_eq!(kept.position(index), Some(next), "survivors keep their order");
                assert_eq!(&output[next], want, "{index} -> {next}");
                next += 1;
            }
        }
        assert_eq!(next, output.len(), "every output is some input");
        assert_eq!(kept.boundary(survivors.len()), output.len());
    }

    #[test]
    fn each_pass_reports_exactly_what_it_dropped() {
        let stream = vec![
            copy(imm(1), "%k"),
            assert_on(var("%k")),
            bits("%a", 64),
            copy(imm(5), "%five"),
            bits("%a", 64),
            assert_on(var("%five")),
            assert_on(var("%p")),
            boolean("%a"),
        ];

        // The fold: both copies go, and both asserts on them now read the
        // immediate — two DISTINCT asserts, each checked at its own place.
        let (folded, kept) = fold_immediate_copies_kept(stream.clone());
        assert_eq!(folded, fold_immediate_copies(stream.clone()));
        check(
            &kept,
            &folded,
            &[
                None,
                Some(assert_on(imm(1))),
                Some(bits("%a", 64)),
                None,
                Some(bits("%a", 64)),
                Some(assert_on(imm(5))),
                Some(assert_on(var("%p"))),
                Some(boolean("%a")),
            ],
        );

        // The true-assert rule: only `assert 1` goes; `assert 5` stays.
        let (dropped, kept) = drop_true_asserts_kept(folded.clone());
        assert_eq!(dropped, drop_true_asserts(folded.clone()));
        let mut want: Vec<Option<Instruction>> = folded.iter().cloned().map(Some).collect();
        want[0] = None;
        check(&kept, &dropped, &want);

        // The dedup: the repeated 64-bit constraint goes; the boolean after
        // it is TIGHTER than 64 bits, so it stays.
        let (deduped, kept) = dedup_range_constraints_kept(dropped.clone());
        assert_eq!(deduped, dedup_range_constraints(dropped.clone()));
        let mut want: Vec<Option<Instruction>> = dropped.iter().cloned().map(Some).collect();
        want[1] = None;
        check(&kept, &deduped, &want);
    }

    #[test]
    fn compose_is_the_conjunction_and_identity_is_neutral() {
        let identity = Kept::identity(3);
        assert_eq!((0..3).map(|i| identity.position(i)).collect::<Vec<_>>(), [Some(0), Some(1), Some(2)]);
        assert_eq!(identity.compose(&identity), identity);

        let (_, first) = retain_kept(
            vec![assert_on(imm(1)), assert_on(var("%p")), assert_on(imm(1))],
            |i| *i == assert_on(var("%p")),
        );
        assert_eq!(first.compose(&Kept::identity(1)), first);
        assert_eq!(Kept::identity(3).compose(&first), first);
    }

    #[test]
    #[should_panic(expected = "Kept::compose: compose the maps in pass order")]
    fn compose_refuses_a_map_of_another_stream() {
        let _ = Kept::identity(1).compose(&Kept::identity(2));
    }

    #[test]
    #[should_panic(expected = "Kept::position: instruction 2 is not in the 2-instruction stream")]
    fn position_refuses_an_index_past_the_stream() {
        let _ = Kept::identity(2).position(2);
    }

    #[test]
    #[should_panic(expected = "Kept::boundary: boundary 3 is past the end of the 2-instruction stream")]
    fn boundary_refuses_an_index_past_the_end() {
        let _ = Kept::identity(2).boundary(3);
    }

    #[test]
    fn the_empty_stream() {
        let (out, kept) = retain_kept(Vec::new(), |_| true);
        assert!(out.is_empty());
        assert_eq!((kept.input_len(), kept.output_len(), kept.boundary(0)), (0, 0, 0));
        assert_eq!(kept.compose(&Kept::identity(0)), kept);
    }

    // ---- random streams -------------------------------------------------------

    /// xorshift64, fixed seed: deterministic, no dependency.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % n
        }
    }

    /// A stream over the shapes the three passes act on: copies of 0, 1 and
    /// 2, copies of copies (chains), asserts on immediates, copies and
    /// inputs, bit and boolean constraints on inputs and copies, and
    /// sometimes an `Output` that keeps one copy named.
    fn stream(r: &mut Rng) -> Vec<Instruction> {
        let n = r.below(16);
        let mut out = Vec::new();
        let made = |k: u64| format!("%c{k}");
        for k in 0..n {
            let instruction = match r.below(8) {
                0 => copy(imm(r.below(3)), &made(k)),
                1 => copy(var(&made(r.below(k + 1))), &made(k)),
                2 => assert_on(imm(r.below(3))),
                3 => assert_on(var(&made(r.below(k + 1)))),
                4 => assert_on(var(&format!("%in{}", r.below(3)))),
                5 => bits(&format!("%in{}", r.below(3)), [1, 8, 64][r.below(3) as usize]),
                6 => boolean(&format!("%in{}", r.below(3))),
                _ => bits(&made(r.below(k + 1)), 8),
            };
            out.push(instruction);
        }
        if n > 0 && r.below(2) == 0 {
            out.push(Instruction::Output {
                vals: vec![var(&made(r.below(n)))],
            });
        }
        out
    }

    /// The true-assert rule's expectation, independently: everything but an
    /// `assert` on the immediate 1 survives unchanged.
    fn check_drop(input: &[Instruction], output: &[Instruction], kept: &Kept) {
        let survivors: Vec<Option<Instruction>> = input
            .iter()
            .map(|i| (*i != assert_on(imm(1))).then(|| i.clone()))
            .collect();
        check(kept, output, &survivors);
    }

    /// The dedup's expectation, independently: a bit or boolean constraint
    /// on a wire is dropped iff an earlier KEPT one on that wire was at
    /// least as tight (boolean counts as one bit); everything else survives
    /// unchanged.
    fn check_dedup(input: &[Instruction], output: &[Instruction], kept: &Kept) {
        let mut tightest: Vec<(Identifier, u32)> = Vec::new();
        let survivors: Vec<Option<Instruction>> = input
            .iter()
            .map(|i| {
                let on = match i {
                    Instruction::ConstrainBits { val: Operand::Variable(id), bits } => Some((id, *bits)),
                    Instruction::ConstrainToBoolean { val: Operand::Variable(id) } => Some((id, 1)),
                    _ => None,
                };
                let Some((id, bits)) = on else {
                    return Some(i.clone());
                };
                match tightest.iter_mut().find(|(w, _)| w == id) {
                    Some((_, proven)) if *proven <= bits => None,
                    Some((_, proven)) => {
                        *proven = bits;
                        Some(i.clone())
                    }
                    None => {
                        tightest.push((id.clone(), bits));
                        Some(i.clone())
                    }
                }
            })
            .collect();
        check(kept, output, &survivors);
    }

    #[test]
    fn every_pass_is_a_filter_and_its_map_says_so_on_random_streams() {
        let mut r = Rng(0x6b65_4316_6b65_4316);
        let mut dropped = [0usize; 3];
        for _ in 0..100_000 {
            let s = stream(&mut r);

            let (f, k1) = fold_immediate_copies_kept(s.clone());
            assert_eq!(f, fold_immediate_copies(s.clone()));
            check_fold(&s, &f, &k1);

            let (d, k2) = drop_true_asserts_kept(f.clone());
            assert_eq!(d, drop_true_asserts(f.clone()));
            check_drop(&f, &d, &k2);

            let (e, k3) = dedup_range_constraints_kept(d.clone());
            assert_eq!(e, dedup_range_constraints(d.clone()));
            check_dedup(&d, &e, &k3);

            // Composition is stepwise `position`, and associative.
            let all = k1.compose(&k2).compose(&k3);
            assert_eq!(all, k1.compose(&k2.compose(&k3)));
            assert_eq!((all.input_len(), all.output_len()), (s.len(), e.len()));
            for i in 0..s.len() {
                let stepwise = k1
                    .position(i)
                    .and_then(|p| k2.position(p))
                    .and_then(|p| k3.position(p));
                assert_eq!(all.position(i), stepwise);
            }
            for i in 0..=s.len() {
                assert_eq!(all.boundary(i), k3.boundary(k2.boundary(k1.boundary(i))));
            }

            dropped[0] += s.len() - f.len();
            dropped[1] += f.len() - d.len();
            dropped[2] += d.len() - e.len();
        }
        // The streams exercise every pass's drop, not just its keep.
        assert!(dropped.iter().all(|&n| n > 10_000), "{dropped:?}");
    }

    /// The fold's law, with its expectation computed independently: an
    /// instruction is dropped iff it is a `Copy` whose value chases (through
    /// copies) to an immediate and whose name is not returned; every other
    /// instruction survives with each operand that names such a copy
    /// replaced by that immediate.
    fn check_fold(input: &[Instruction], output: &[Instruction], kept: &Kept) {
        let returned: Vec<&Operand> = input
            .iter()
            .flat_map(|i| match i {
                Instruction::Output { vals } => vals.iter().collect(),
                _ => Vec::new(),
            })
            .collect();
        let mut value: Vec<(String, Operand)> = Vec::new();
        for i in input {
            if let Instruction::Copy { val, output } = i {
                let v = match val {
                    Operand::Immediate(_) => Some(val.clone()),
                    Operand::Variable(id) => {
                        value.iter().find(|(k, _)| *k == id.0).map(|(_, v)| v.clone())
                    }
                };
                if let Some(v) = v {
                    value.push((output.0.clone(), v));
                }
            }
        }
        // Later definitions shadow earlier ones; the streams never reuse a
        // name, so the first match is the only one.
        let folded = |id: &Identifier| -> Option<Operand> {
            if returned.contains(&&Operand::Variable(id.clone())) {
                return None;
            }
            value.iter().find(|(k, _)| *k == id.0).map(|(_, v)| v.clone())
        };
        let subst = |op: &Operand| match op {
            Operand::Variable(id) => folded(id).unwrap_or_else(|| op.clone()),
            Operand::Immediate(_) => op.clone(),
        };
        let survivors: Vec<Option<Instruction>> = input
            .iter()
            .map(|i| match i {
                Instruction::Copy { output, .. } if folded(output).is_some() => None,
                Instruction::Copy { val, output } => Some(copy(subst(val), &output.0)),
                Instruction::Assert { cond } => Some(assert_on(subst(cond))),
                Instruction::ConstrainBits { val, bits } => Some(Instruction::ConstrainBits {
                    val: subst(val),
                    bits: *bits,
                }),
                Instruction::ConstrainToBoolean { val } => {
                    Some(Instruction::ConstrainToBoolean { val: subst(val) })
                }
                other => Some(other.clone()),
            })
            .collect();
        check(kept, output, &survivors);
    }
}
