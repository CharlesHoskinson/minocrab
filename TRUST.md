# TRUST.md — what a human must read, in what order

Most of this tree is warranted by machinery: the differentials against
compactc's own artifacts, the frozen snapshots, the spec-and-property
harness, the reference-VM cross-check, the Lean gates. The part that is
not is small and nameable, and this document names it — file by file,
with the test or proof that would catch a wrong line, and the failure that
would hide there if nothing did. The rows whose warrant is **READING** are
the trusted computing base. Everything else is where a reviewer's hour
buys the least, because a machine already stands there.

The table is generated (`crates/minocrab-contracts/tests/trust_base.rs`):
the classification is data in that test, the line counts are measured, and
a test fails when a source file of the seven eDSL crates has no row, a row
names a file that is gone, or this table is stale. Regenerate with
`MINOCRAB_TRUST_BASE=1 cargo test -p minocrab-contracts --test trust_base`
and review the diff. THE ONE ERROR THIS TABLE MUST NOT CONTAIN is a warrant
claimed that is not there: where unsure, a row says READING and you
downgrade it, never the reverse.

[VERIFICATION.md](VERIFICATION.md) is the companion: it says what each
suite warrants; this says where the suites stop.

## 1. The inventory

<!-- GENERATED BEGIN: trust_base.rs -->
| file | lines | what warrants it | the failure that would hide there |
|---|---:|---|---|
| `minocrab-zkir/src/lib.rs` | 67 | corpus_roundtrip (92 v3 artifacts, count asserted); lean_roundtrip (byte-exact Lean syntax, M27 rung 1) | a `.zkir` envelope or version read wrongly — every differential reads compactc's artifacts through here |
| `minocrab-zkir/src/v3.rs` | 72 | corpus_roundtrip; lean_roundtrip; every differential (reads compactc's artifact through this pair) | an IR re-emitted differently from what was parsed |
| `minocrab-ir/src/lib.rs` | 41 | **READING** | nothing beyond re-exports (41 lines) |
| `minocrab-ir/src/v3.rs` | 961 | every instruction-level differential (the emitted stream equals compactc's); v3_builder. The operand-type TABLES themselves: **READING** against zkir-v3/src/ir_vm.rs | an instruction emitted with an operand type the VM rejects, on a path no fixture takes |
| `minocrab-ir/src/v3/passes.rs` | 1221 | Lean (crates/minocrab-ir/lean, the pass theorems, M25/M27); v3_passes; the zkir dump + row snapshot (every pass is zero-movement on the shipped artifacts) | a pass that changes a circuit's statement while preserving its rows |
| `minocrab-ir/src/v3/taint.rs` | 2088 | Kani harnesses (./kani.sh, M23 R4) + unit tests for the Max arithmetic; 18 unit tests over the marking rules, the three subtraction warrants' near-miss refusals and the observability walk's refused sinks; the MARKING RULES' warrants are cited in-file per rule and are READING. The observability walk (M23 R3 Class A) reads operands through passes::operands / defined_identifiers, which the Lean dataflow gate diffs | a limb marked bounded that is not, or a guarded read discharged as unobservable whose digest in fact reaches an effect the walk's sink classification waves through — a false negative in the one lint that sees what honest inputs cannot |
| `minocrab/src/lib.rs` | 192 | compile_fail doctests (a private wire cannot reach an output); READING for the lattice itself (192 lines) | a Meet impl that lets private meet public as public |
| `minocrab/src/v3.rs` | 2061 | every differential (the streams Circuit3 emits); v3_guard_scope (guard scopes); the generated disclosure set-equality tests + compile_fail (the disclose gate). The instruction methods' operand/immediate handling and public_input minting: **READING** against reduce-to-zkir.ss | a guard dropped on one effect inside `when`; a public input minted in the wrong order |
| `minocrab/src/v3/abi.rs` | 607 | v3_entry / v3_leaves / v3_bounded (the constraint table pinned to compactc's, notes/builtin-lowering.org §9); interface_snapshot | an argument type constrained to the wrong width |
| `minocrab/src/v3/disclose.rs` | 580 | the generated set-equality test on every circuit; disclosure_report; v3_disclose | a disclosure recorded under a label the signature does not name |
| `minocrab/src/v3/effects.rs` | 318 | v3_guard_scope; every differential with a branch | an effect escaping its guard |
| `minocrab-ledger/src/lib.rs` | 105 | **READING** | nothing beyond the crate doc and mod/pub-use plumbing (102 lines) |
| `minocrab-ledger/src/impact.rs` | 357 | differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (315 contracts). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): **READING** against midnight-ledger.ss vm-code | an Impact op encoded so the ledger applies a different state change than the circuit claims |
| `minocrab-ledger/src/ops.rs` | 1210 | differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (315 contracts). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): **READING** against midnight-ledger.ss vm-code | an Impact op encoded so the ledger applies a different state change than the circuit claims |
| `minocrab-ledger/src/reads.rs` | 553 | differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (315 contracts). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): **READING** against midnight-ledger.ss vm-code | an Impact op encoded so the ledger applies a different state change than the circuit claims |
| `minocrab-ledger/src/kernel.rs` | 324 | differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (315 contracts). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): **READING** against midnight-ledger.ss vm-code | an Impact op encoded so the ledger applies a different state change than the circuit claims |
| `minocrab-ledger/src/calls.rs` | 306 | differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (315 contracts). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): **READING** against midnight-ledger.ss vm-code | an Impact op encoded so the ledger applies a different state change than the circuit claims |
| `minocrab-ledger/src/tests.rs` | 1037 | **READING** | a unit test that pins the wrong constant or asserts a weaker property than intended, unnoticed because it still passes |
| `minocrab-std/src/lib.rs` | 51 | **READING** | nothing beyond re-exports (51 lines) |
| `minocrab-std/src/v3.rs` | 2661 | every differential; v3_leaves / v3_bounded / v3_literals / v3_secp; lean_claims (the typed-leaf claims, crates/minocrab-std/lean). `from_field_unchecked` sites: **READING** (the grep in TRUST.md §3) | a leaf whose type promises a bound its constructor did not constrain |
| `minocrab-std/src/v3/ledger.rs` | 2075 | every contract differential; v3_ledger; nested_typed; the derive's layout pinned against compactc's `batch` for all 256 block sizes and the sixteen-field probe | a typed slot reading the wrong field, or a segmented path computed differently from compactc |
| `minocrab-std/src/v3/borsh.rs` | 1182 | serialization_conformance (vectors shared with the published TypeScript decoder, spec/ts); v3_borsh; the borsh differentials | a non-canonical encoding accepted, breaking the digest's injectivity (api-safety-survey §B3) |
| `minocrab-std/src/v3/borsh/schema.rs` | 181 | the generated schema cross-check test per #[derive(CircuitBorsh)] (layout ≡ borsh's schema of the spec type) | a layout table disagreeing with the published spec |
| `minocrab-std/src/v3/kernel.rs` | 782 | kernel_tokens_differential (24 circuits, byte-identical); v3_kernel_cache | a kernel effect claimed at the wrong effects index |
| `minocrab-std/src/v3/blind.rs` | 424 | v3_blind (every blind op run on Midnight's on-chain VM against a seeded state, zero reads asserted; the typed spellings byte-identical to the explicit op lists); v3_stream; evm_outbox | a blind combine or snapshot that lands a different value than the step defines, or one that embeds a read |
| `minocrab-std/src/v3/hook.rs` | 423 | v3_hook (every builder method on the on-chain VM, each failure row of the design table, attachment order, guard capture, the after-the-body rule; a composite hook byte-identical to the explicit op lists); the two compile-fail doctests | a hook lowered to ops that read, or emitted under the wrong guard or before an inline effect |
| `minocrab-std/src/v3/assumed.rs` | 181 | v3_ledger and every contract differential (the wrapper is erased in the ZKIR: byte-identical artifacts); the compile-fail doctest; the backstop's refusals in the contract suites named every read-modify-write in the corpus | a read result re-entering the ledger with nothing naming the assumption — a contended write nobody sees as one |
| `minocrab-std/src/v3/stream.rs` | 368 | v3_stream (insert / take / combine / sequence on the on-chain VM, both layouts); evm_outbox (the contention audit); fee_ema (flushes of one to four); the two compile-fail doctests | a stream operation reading the shared accumulator where the design says it must not |
| `minocrab-std/src/v3/vector.rs` | 355 | v3_vector (fold and for_each on the VM: live slots only, the guard and the select; the all-dead case unexpressible); v3_bounded | a fold applying its step, or a ledger op, on a dead slot |
| `minocrab-std/src/v3/entry.rs` | 917 | interface_snapshot (every circuit's argument schema frozen); v3_entry; every differential | an argument declared in a different slot order than the wire |
| `minocrab-std/src/v3/predicate.rs` | 681 | v3_predicates; every differential with a comparison | a comparison at the wrong width, or a message-carrying assert that binds outside its branch |
| `minocrab-std/src/v3/call.rs` | 254 | xcall_differential / xcall_with_payment_differential / xcontract_events_differential; interface_macro; contract_matches_its_interface | call limbs hashed into the communications commitment in the wrong order |
| `minocrab-std/src/v3/disclose.rs` | 212 | v3_disclose; the generated set-equality tests | a leaf disclosed under fewer wires than it has |
| `minocrab-std/src/v3/hash.rs` | 195 | hashing_differential; every differential that hashes | a preimage aligned differently from compactc's |
| `minocrab-macros/src/lib.rs` | 325 | **READING** | nothing beyond wrappers (the expansions are the modules below) |
| `minocrab-macros/src/circuit.rs` | 896 | v3_circuit (the expansion lowers to ZKIR byte-identical to the hand-written twin); the generated per-circuit tests run on every circuit. The GENERATED TESTS' own bodies: **READING** | an expansion that declares an argument the twin would not, or a generated test that passes vacuously |
| `minocrab-macros/src/circuit_arg.rs` | 530 | v3_derive (twin); every derived struct's slots in interface_snapshot | a field's slots declared out of order |
| `minocrab-macros/src/circuit_borsh.rs` | 495 | v3_borsh_derive (twin) + the generated schema cross-check | a Borsh field encoded at the wrong width |
| `minocrab-macros/src/interface.rs` | 620 | interface_macro (twin, byte-identical ZKIR); contract_matches_its_interface | a call handle passing limbs in an order the callee does not expect |
| `minocrab-macros/src/ledger.rs` | 430 | the derive's unit tests; in_block pinned against `batch` for every block size (minocrab-std); the sixteen-field compactc probe | a ledger field laid out at a path compactc would not use |
| `minocrab-macros/src/ledger_repr.rs` | 158 | v3_ledger `derived_repr` (atoms and limb round trip); the erc20_vault_pending lineage's slots | an environment's limbs split at the wrong boundaries on read-back |
| `minocrab-macros/src/contract.rs` | 229 | circuit_closure (every #[circuit] is listed) + the derived sets feeding both snapshots | a circuit missing from its contract's set |
| `minocrab-sim/src/lib.rs` | 129 | **READING** | nothing beyond the Profile types (129 lines) |
| `minocrab-sim/src/v3.rs` | 1315 | cross-checked against Midnight's reference VM (`IrSource::check`) on every accepted run — spec-harness link 4 and every differential; v3_end_to_end. It is never trusted alone | a simulator accepting what the reference VM rejects (caught) — or both agreeing on a wrong statement (out of scope here; the differentials' job) |
| `minocrab-sim/src/v3/exec.rs` | 763 | executor_vault (the transcript it derives from state equals the vault harness's hand model, op for op, on seventeen circuits) + IrSource::check on every preimage it produces; impact_roundtrip (the decoder is the exact inverse of minocrab-ledger's encoder, one fixture per Op::field_repr branch). Test-side only: nothing a deployed circuit links | a mis-decoded Impact op — a transcript that gathers a read from the wrong slot, agreeing with nothing (caught by the harness) unless the hand model is wrong the same way |
| `minocrab-sim/src/v3/rowcost.rs` | 391 | calibrated against real proving (BENCHMARK.md); a MEASUREMENT model, not a correctness claim | a mis-priced primitive — a wrong k estimate, never a wrong circuit |
| `minocrab-sim/src/bin/minocrab.rs` | 222 | **READING** | nothing a proof depends on (the CLI) |

29545 lines in the seven crates; 11239 of them in files whose warrant is READING in whole or in part (the rows in bold).
<!-- GENERATED END -->

## 2. The read order, with a time budget

Bottom of the stack first, because every layer above is written against
the one below. Times are for someone who knows Midnight's ledger and ZKIR
v3 internals; double them otherwise. Each item says what to compare against
in the pinned ledger checkout (`midnight-ledger` at `04c9c5d9`, the rev in
`Cargo.toml`) and in compactc's compiler sources (`corpus/src/compact/`).

| # | read | budget | the question it answers | compare against |
|---|---|---|---|---|
| 1 | `crates/minocrab-zkir/src/` (139 lines) | 15 min | is the IR type Midnight's own, re-exported, and is the file envelope the only thing added? | `zkir-v3/src/ir.rs` — nothing here should redefine a type |
| 2 | `crates/minocrab/src/lib.rs` (192) | 15 min | is the visibility lattice sound: can private meet public and come out public anywhere? | the four `Meet` impls, by hand |
| 3 | `crates/minocrab-ir/src/v3.rs` (882) | 1.5 h | does every instruction's operand-type table match what the VM accepts, including immediates? | `zkir-v3/src/ir_vm.rs` (`preprocess`, the per-instruction arms) |
| 4 | `crates/minocrab/src/v3.rs` (1,731) | 3 h | the disclosure gate (one method, `disclose*`), the guard scopes (`when`, `guarded`), public-input minting order; can an effect escape its guard? | `compiler/zkir-v3-passes/reduce-to-zkir.ss` for the guard and read conventions; `tests/v3_guard_scope.rs` for what is pinned |
| 5 | `crates/minocrab-ledger/src/{impact,ops,reads,kernel,calls}.rs` (2,695; split by concern, M26 — `lib.rs` itself is now 103 lines of crate doc and re-exports, and `tests.rs` is the crate's own unit tests) | 4 h | is each Impact op encoded as compactc's vm-code says, and does every read mint its gates before the op? Concentrate on ops no fixture reaches (VERIFICATION.md §5) | `compiler/midnight-ledger.ss` (vm-code per kernel/ADT function), `ledger/src/verify.rs` (transcript rules) |
| 6 | `crates/minocrab-macros/src/` (3,388) | 2 h | do the expansions add anything the hand-written twins do not — argument order, constraints, the generated tests' bodies? | the twin tests (`v3_circuit`, `v3_derive`, `interface_macro`): read the twin, then the expansion |
| 7 | `crates/minocrab-sim/src/v3.rs` (1,169) | 1.5 h | is the simulator a port of `preprocess`, and is it ever trusted alone? | `zkir-v3/src/ir_vm.rs::preprocess`; `IrSource::check` at every call site of `simulate` |
| 8 | `crates/minocrab-ir/src/v3/passes.rs`, `taint.rs` (2,323) | 2 h | does each pass have its Lean theorem, and does each taint marking rule cite an in-circuit warrant? | `crates/minocrab-ir/lean/`; `notes/taint-lint.org §4` |
| 9 | `crates/minocrab-std/src/v3/` (9,598) | 1 day | not line by line: the SEAMS — every `from_field_unchecked`, every `.field()` that drops a range obligation, every `or_default()` | the greps in §3; `notes/api-safety-survey.org §A1-A2` |

About three days for the READING rows plus the seams; the differentials
cover the rest and a reviewer's time is better spent running them
(VERIFICATION.md §6 has the one-day gate run).

## 3. The checklist — the escape hatches, greppable by design

Run against `crates/*/src`. Each hit is a place where an obligation is
discharged by hand rather than by a type:

```
grep -rn 'from_field_unchecked'      # the unchecked type claim; the twin is from_field_checked
grep -rn '\.field()'                 # a typed leaf becoming a raw wire — the range obligation drops here
grep -rn 'or_default()'              # a guarded-off read consumed as the type's default
grep -rnE 'disclose(_as)?\('         # every private→public transition, each declared in a signature
grep -rnE 'PRECONDITION|caller.s job'  # invariants in prose rather than checked
grep -rn 'unsafe'                    # should be empty in the eDSL crates
```

The taint lint (`tests/taint_lint.rs`) is the one instrument that sees the
class no test on honest inputs can; its frozen baseline is classified in
`notes/taint-lint.org §5`, and a reviewer should read the baseline as a
list of open questions, not as accepted findings.

## 4. What this document does not cover

The contracts crate (the vault lineages, the corpus ports) is warranted by
its differentials and the spec harness and is not inventoried here; the
`signet-sim` crate is a test aid; the interface crates are generated from
artifacts and gated by `artifact_agreement`. The design of record for this
inventory, including how the warrant column was decided, is
[notes/trust-base.org](notes/trust-base.org).
