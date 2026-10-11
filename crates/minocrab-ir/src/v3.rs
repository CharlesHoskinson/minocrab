//! L1 for ZKIR v3 — typed circuit builder over the v3 instruction set.
//!
//! v3 differs from v2 (see `lib.rs`) in three ways that shape this API:
//! values are *named* (`%label.N` identifiers, matching compactc's
//! convention) rather than memory indices; values are *typed* ([`IrType`]:
//! native field, `Bytes<32>`, and the foreign-curve types); and immediates
//! appear inline as operands instead of via `LoadImm`. [`Builder3`] tracks
//! the type of every value and panics at circuit-build time on an operand
//! type an instruction does not support (the lists in midnight-ledger
//! `zkir-v3/src/ir.rs` doc comments), so a type error can never reach the
//! prover. Semantics reference: `zkir-v3/src/ir_vm.rs`.

#[cfg(feature = "unstable")]
use std::sync::Arc;

#[cfg(feature = "unstable")]
use minocrab_zkir::Fr;
pub use minocrab_zkir::v3::{Identifier, Instruction, IrSource, IrType, Operand, TypedIdentifier};

pub use midnight_base_crypto::fab::Alignment;

pub mod passes;
pub mod taint;

#[cfg(feature = "unstable")]
/// A handle to one named, typed circuit value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Val(u32);

#[cfg(feature = "unstable")]
/// An instruction operand: a built value or an inline immediate (immediates
/// are native field elements).
#[derive(Debug, Clone, Copy)]
pub enum Arg {
    Val(Val),
    Imm(Fr),
}

#[cfg(feature = "unstable")]
impl From<Val> for Arg {
    fn from(v: Val) -> Self {
        Arg::Val(v)
    }
}

#[cfg(feature = "unstable")]
impl From<Fr> for Arg {
    fn from(imm: Fr) -> Self {
        Arg::Imm(imm)
    }
}

#[cfg(feature = "unstable")]
impl From<u64> for Arg {
    fn from(imm: u64) -> Self {
        Arg::Imm(imm.into())
    }
}

#[cfg(feature = "unstable")]
fn is_foreign_field(ty: &IrType) -> bool {
    matches!(
        ty,
        IrType::Secp256k1Base
            | IrType::Secp256k1Scalar
            | IrType::Secp256r1Base
            | IrType::Secp256r1Scalar
            | IrType::Curve25519Base
            | IrType::Curve25519Scalar
    )
}

#[cfg(feature = "unstable")]
fn is_point(ty: &IrType) -> bool {
    matches!(
        ty,
        IrType::JubjubPoint
            | IrType::Secp256k1Point
            | IrType::Secp256r1Point
            | IrType::Curve25519Point
    )
}

#[cfg(feature = "unstable")]
/// TestEq/Add/Neg/CondSelect/ConstrainEq support everything except
/// `Bytes<32>` and `Scalar<Jubjub>`.
fn supports_eq_add(ty: &IrType) -> bool {
    matches!(ty, IrType::Native) || is_foreign_field(ty) || is_point(ty)
}

#[cfg(feature = "unstable")]
/// Mul/Inv support field elements only (no points).
fn supports_mul(ty: &IrType) -> bool {
    matches!(ty, IrType::Native) || is_foreign_field(ty)
}

#[cfg(feature = "unstable")]
/// IntoBytes32/FromBytes32 support prime-field elements with a canonical
/// 32-byte little-endian form.
fn supports_bytes32_conversion(ty: &IrType) -> bool {
    matches!(ty, IrType::Native) || is_foreign_field(ty)
}

#[cfg(feature = "unstable")]
/// The affine-coordinate type of each curve's points.
fn coordinate_type(point: &IrType) -> Option<IrType> {
    match point {
        IrType::JubjubPoint => Some(IrType::Native),
        IrType::Secp256k1Point => Some(IrType::Secp256k1Base),
        IrType::Secp256r1Point => Some(IrType::Secp256r1Base),
        IrType::Curve25519Point => Some(IrType::Curve25519Base),
        _ => None,
    }
}

#[cfg(feature = "unstable")]
/// The scalar type matching each curve's points, for EcMul.
fn scalar_type(point: &IrType) -> Option<IrType> {
    match point {
        IrType::JubjubPoint => Some(IrType::JubjubScalar),
        IrType::Secp256k1Point => Some(IrType::Secp256k1Scalar),
        IrType::Secp256r1Point => Some(IrType::Secp256r1Scalar),
        IrType::Curve25519Point => Some(IrType::Curve25519Scalar),
        _ => None,
    }
}

#[cfg(feature = "unstable")]
/// Construct a [`TypedIdentifier`]; its fields are `pub(crate)` upstream, so
/// go through its serde form (`{"name": ..., "type": ...}`).
fn typed_identifier(name: &Identifier, ty: &IrType) -> TypedIdentifier {
    let value = serde_json::json!({
        "name": name.0,
        "type": serde_json::to_value(ty).expect("IrType serializes"),
    });
    serde_json::from_value(value).expect("TypedIdentifier deserializes from name + type")
}

#[cfg(feature = "unstable")]
/// Builds a ZKIR v3 instruction stream with statically-tracked, typed,
/// named values.
#[derive(Debug, Default)]
pub struct Builder3 {
    /// Name and type of every value, indexed by [`Val`]. The first
    /// `inputs.len()` slots are the circuit arguments.
    names: Vec<Identifier>,
    types: Vec<IrType>,
    inputs: Vec<TypedIdentifier>,
    instructions: Vec<Instruction>,
    /// Set by [`Builder3::output`]; a v3 circuit has at most one Output
    /// terminator, whose operand types are the circuit's output signature.
    outputs: Option<Vec<IrType>>,
    /// Set by [`Builder3::dedup_range_constraints`]; OFF by default, because
    /// the pass diverges from compactc (notes/ir-passes.org §1).
    dedup_constraints: bool,
}

#[cfg(feature = "unstable")]
impl Builder3 {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a fresh value named `%label.N` of type `ty`.
    fn fresh(&mut self, label: &str, ty: IrType) -> Val {
        let index = self.names.len();
        self.names.push(Identifier(format!("%{label}.{index}")));
        self.types.push(ty);
        Val(index as u32)
    }

    fn name(&self, v: Val) -> Identifier {
        self.names[v.0 as usize].clone()
    }

    /// The identifier a value was registered under (`%label.N`) — the name
    /// the instruction stream refers to it by, and the key the simulator's
    /// value memory uses. Reads nothing and builds nothing; it exists so the
    /// disclosure record can point at a value (v2 records a memory index,
    /// which v3 does not have).
    pub fn identifier(&self, v: Val) -> Identifier {
        self.name(v)
    }

    fn operand(&self, arg: Arg) -> Operand {
        match arg {
            Arg::Val(v) => Operand::Variable(self.name(v)),
            Arg::Imm(imm) => Operand::Immediate(imm),
        }
    }

    /// The type of an operand; immediates are native field elements.
    pub fn ty(&self, arg: impl Into<Arg>) -> IrType {
        match arg.into() {
            Arg::Val(v) => self.types[v.0 as usize].clone(),
            Arg::Imm(_) => IrType::Native,
        }
    }

    #[track_caller]
    fn expect(&self, arg: Arg, pred: impl Fn(&IrType) -> bool, what: &str, op: &str) {
        let ty = self.ty(arg);
        assert!(pred(&ty), "{op}: operand must be {what}, got {ty:?}");
    }

    #[track_caller]
    fn expect_native(&self, arg: Arg, op: &str) {
        self.expect(arg, |t| matches!(t, IrType::Native), "Native", op);
    }

    #[track_caller]
    fn expect_same(&self, a: Arg, b: Arg, op: &str) -> IrType {
        let (ta, tb) = (self.ty(a), self.ty(b));
        assert!(ta == tb, "{op}: operand types differ: {ta:?} vs {tb:?}");
        ta
    }

    fn natives(&self, args: &[Arg], op: &str) -> Vec<Operand> {
        args.iter()
            .map(|&a| {
                self.expect_native(a, op);
                self.operand(a)
            })
            .collect()
    }

    // --- circuit arguments ----------------------------------------------------

    /// Declare the next circuit argument (arguments are witness data, as in
    /// v2). Must precede all instructions.
    pub fn input(&mut self, label: &str, ty: IrType) -> Val {
        assert!(
            self.instructions.is_empty(),
            "inputs must be declared before instructions"
        );
        let val = self.fresh(label, ty.clone());
        self.inputs.push(typed_identifier(&self.name(val), &ty));
        val
    }

    // --- value-producing instructions ------------------------------------------

    /// A named native constant. v3 has no LoadImm — immediates are inline
    /// operands (every `Arg`-taking method accepts an `Fr` directly) — but a
    /// `Copy` gives one a reusable name without extending the circuit.
    pub fn imm(&mut self, imm: impl Into<Fr>) -> Val {
        let output = self.fresh("imm", IrType::Native);
        self.instructions.push(Instruction::Copy {
            val: Operand::Immediate(imm.into()),
            output: self.name(output),
        });
        output
    }

    /// The immediate a value NAMES, if it was bound by a `Copy` of one — the
    /// question the disclosure layer asks before recording a wire, since the
    /// folding pass will inline such a copy away (`passes`).
    pub fn immediate_of(&self, val: Val) -> Option<Fr> {
        let name = self.name(val);
        self.instructions
            .iter()
            .rev()
            .find_map(|instruction| match instruction {
                Instruction::Copy {
                    val: Operand::Immediate(imm),
                    output,
                } if *output == name => Some(*imm),
                _ => None,
            })
    }

    /// Whether `val` is the output of a PUBLIC transcript read — a ledger
    /// read's witnessed value.
    pub fn is_public_input(&self, val: Val) -> bool {
        let name = self.name(val);
        self.instructions.iter().any(|instruction| {
            matches!(instruction, Instruction::PublicInput { output, .. } if *output == name)
        })
    }

    /// The index of the instruction that binds `val`, if one does (a circuit
    /// argument has none).
    pub fn instruction_index_of(&self, val: Val) -> Option<usize> {
        let name = self.name(val);
        self.instructions
            .iter()
            .position(|instruction| passes::defined_identifiers(instruction).contains(&name))
    }

    /// The public transcript reads `val` DESCENDS FROM: every `public_input`
    /// output reachable backwards through the operands of the instructions
    /// that built it, not looking behind any value for which `stop` holds.
    /// Dataflow provenance, the question the stale-read backstop asks
    /// (notes/hooks-design.org): the types track direct read results, this
    /// tracks what was computed from them.
    pub fn transcript_reads_behind(&self, val: Val, stop: &dyn Fn(Val) -> bool) -> Vec<Val> {
        use std::collections::{HashMap, HashSet};
        let val_of: HashMap<&Identifier, Val> = self
            .names
            .iter()
            .enumerate()
            .map(|(i, name)| (name, Val(i as u32)))
            .collect();
        let mut defs: HashMap<&Identifier, usize> = HashMap::new();
        for (i, instruction) in self.instructions.iter().enumerate() {
            for name in passes::defined_identifiers(instruction) {
                if let Some((key, _)) = val_of.get_key_value(&name) {
                    defs.insert(key, i);
                }
            }
        }
        let mut reads = Vec::new();
        let mut seen: HashSet<Val> = HashSet::new();
        let mut stack = vec![val];
        while let Some(v) = stack.pop() {
            if !seen.insert(v) || stop(v) {
                continue;
            }
            let Some(&i) = defs.get(&self.names[v.0 as usize]) else {
                continue; // a circuit argument
            };
            let instruction = &self.instructions[i];
            if matches!(instruction, Instruction::PublicInput { .. }) {
                reads.push(v);
                continue;
            }
            for operand in passes::operands(instruction) {
                if let Operand::Variable(id) = operand {
                    if let Some(&w) = val_of.get(&id) {
                        stack.push(w);
                    }
                }
            }
        }
        reads
    }

    /// Whether `val` is the output of a transcript read (`private_input` /
    /// `public_input`) carrying exactly `guard` as its guard operand.
    ///
    /// The question a range check inside a guarded scope asks before it
    /// selects: a guarded read yields the type's default — zero — where its
    /// guard is off, so a bit or boolean constraint on it already holds on
    /// the path not taken and needs no `cond_select` in front of it. That
    /// is compactc's own shape for a guarded read (the witnesses carry the
    /// branch guard, the bit constraints stay bare — claim.zkir:436-439),
    /// and the rule is sound only for the SAME guard: a read guarded by an
    /// outer scope and checked under an inner one gets the select.
    pub fn is_read_guarded_by(&self, val: Val, guard: Val) -> bool {
        let name = self.name(val);
        let guard = self.name(guard);
        self.instructions
            .iter()
            .rev()
            .any(|instruction| match instruction {
                Instruction::PrivateInput {
                    guard: Some(Operand::Variable(g)),
                    output,
                    ..
                }
                | Instruction::PublicInput {
                    guard: Some(Operand::Variable(g)),
                    output,
                    ..
                } => *output == name && *g == guard,
                _ => false,
            })
    }

    /// Copy a value (does not extend the actual circuit).
    pub fn copy(&mut self, val: impl Into<Arg>) -> Val {
        let val = val.into();
        let output = self.fresh("copy", self.ty(val));
        self.instructions.push(Instruction::Copy {
            val: self.operand(val),
            output: self.name(output),
        });
        output
    }

    /// `a + b` (field elements of any one type, or curve points).
    pub fn add(&mut self, a: impl Into<Arg>, b: impl Into<Arg>) -> Val {
        let (a, b) = (a.into(), b.into());
        self.expect(a, supports_eq_add, "a field element or point", "add");
        self.expect(b, supports_eq_add, "a field element or point", "add");
        let ty = self.expect_same(a, b, "add");
        let output = self.fresh("add", ty);
        self.instructions.push(Instruction::Add {
            a: self.operand(a),
            b: self.operand(b),
            output: self.name(output),
        });
        output
    }

    /// `a * b` (field elements of any one type).
    pub fn mul(&mut self, a: impl Into<Arg>, b: impl Into<Arg>) -> Val {
        let (a, b) = (a.into(), b.into());
        self.expect(a, supports_mul, "a field element", "mul");
        self.expect(b, supports_mul, "a field element", "mul");
        let ty = self.expect_same(a, b, "mul");
        let output = self.fresh("mul", ty);
        self.instructions.push(Instruction::Mul {
            a: self.operand(a),
            b: self.operand(b),
            output: self.name(output),
        });
        output
    }

    /// `-a` (field element or point).
    pub fn neg(&mut self, a: impl Into<Arg>) -> Val {
        let a = a.into();
        self.expect(a, supports_eq_add, "a field element or point", "neg");
        let output = self.fresh("neg", self.ty(a));
        self.instructions.push(Instruction::Neg {
            a: self.operand(a),
            output: self.name(output),
        });
        output
    }

    /// `a^(-1)` (field element); errors at proving time if `a` is zero.
    pub fn inv(&mut self, a: impl Into<Arg>) -> Val {
        let a = a.into();
        self.expect(a, supports_mul, "a field element", "inv");
        let output = self.fresh("inv", self.ty(a));
        self.instructions.push(Instruction::Inv {
            a: self.operand(a),
            output: self.name(output),
        });
        output
    }

    /// Boolean not; the operand must hold 0 or 1.
    pub fn not(&mut self, a: impl Into<Arg>) -> Val {
        let a = a.into();
        self.expect_native(a, "not");
        let output = self.fresh("not", IrType::Native);
        self.instructions.push(Instruction::Not {
            a: self.operand(a),
            output: self.name(output),
        });
        output
    }

    /// Boolean (native) `a == b` over any one supported type.
    pub fn test_eq(&mut self, a: impl Into<Arg>, b: impl Into<Arg>) -> Val {
        let (a, b) = (a.into(), b.into());
        self.expect(a, supports_eq_add, "a field element or point", "test_eq");
        self.expect(b, supports_eq_add, "a field element or point", "test_eq");
        self.expect_same(a, b, "test_eq");
        let output = self.fresh("eq", IrType::Native);
        self.instructions.push(Instruction::TestEq {
            a: self.operand(a),
            b: self.operand(b),
            output: self.name(output),
        });
        output
    }

    /// `a < b` over `bits`-bit native values. UB if either exceeds `bits`.
    pub fn less_than(&mut self, a: impl Into<Arg>, b: impl Into<Arg>, bits: u32) -> Val {
        let (a, b) = (a.into(), b.into());
        self.expect_native(a, "less_than");
        self.expect_native(b, "less_than");
        let output = self.fresh("lt", IrType::Native);
        self.instructions.push(Instruction::LessThan {
            a: self.operand(a),
            b: self.operand(b),
            bits,
            output: self.name(output),
        });
        output
    }

    /// `bit ? a : b`; `bit` must hold 0 or 1.
    pub fn cond_select(
        &mut self,
        bit: impl Into<Arg>,
        a: impl Into<Arg>,
        b: impl Into<Arg>,
    ) -> Val {
        let (bit, a, b) = (bit.into(), a.into(), b.into());
        self.expect_native(bit, "cond_select");
        self.expect(a, supports_eq_add, "a field element or point", "cond_select");
        self.expect(b, supports_eq_add, "a field element or point", "cond_select");
        let ty = self.expect_same(a, b, "cond_select");
        let output = self.fresh("sel", ty);
        self.instructions.push(Instruction::CondSelect {
            bit: self.operand(bit),
            a: self.operand(a),
            b: self.operand(b),
            output: self.name(output),
        });
        output
    }

    /// Split a native value into `(val >> bits, val mod 2^bits)`.
    pub fn div_mod_power_of_two(&mut self, val: impl Into<Arg>, bits: u32) -> (Val, Val) {
        let val = val.into();
        self.expect_native(val, "div_mod_power_of_two");
        let div = self.fresh("div", IrType::Native);
        let modulus = self.fresh("mod", IrType::Native);
        self.instructions.push(Instruction::DivModPowerOfTwo {
            val: self.operand(val),
            bits,
            outputs: vec![self.name(div), self.name(modulus)],
        });
        (div, modulus)
    }

    /// `divisor * 2^bits + modulus`, checked against field overflow.
    pub fn reconstitute_field(
        &mut self,
        divisor: impl Into<Arg>,
        modulus: impl Into<Arg>,
        bits: u32,
    ) -> Val {
        let (divisor, modulus) = (divisor.into(), modulus.into());
        self.expect_native(divisor, "reconstitute_field");
        self.expect_native(modulus, "reconstitute_field");
        let output = self.fresh("recon", IrType::Native);
        self.instructions.push(Instruction::ReconstituteField {
            divisor: self.operand(divisor),
            modulus: self.operand(modulus),
            bits,
            output: self.name(output),
        });
        output
    }

    // --- hashes -----------------------------------------------------------------

    /// Poseidon-family in-circuit hash of native field elements.
    pub fn transient_hash(&mut self, inputs: &[Arg]) -> Val {
        let inputs = self.natives(inputs, "transient_hash");
        let output = self.fresh("thash", IrType::Native);
        self.instructions.push(Instruction::TransientHash {
            inputs,
            output: self.name(output),
        });
        output
    }

    /// SHA-256 persistent hash of `inputs` laid out per `alignment`;
    /// the result is a `Bytes<32>` value.
    pub fn persistent_hash(&mut self, alignment: Alignment, inputs: &[Arg]) -> Val {
        // Input types are not constrained here: the alignment governs the
        // preimage layout (zkir-v3 encodes each operand per its type).
        let inputs = inputs.iter().map(|&a| self.operand(a)).collect();
        let output = self.fresh("phash", IrType::Bytes32);
        self.instructions.push(Instruction::PersistentHash {
            alignment,
            inputs,
            output: self.name(output),
        });
        output
    }

    /// Keccak-256 of `inputs` laid out per `alignment`; result is `Bytes<32>`.
    pub fn keccak256(&mut self, alignment: Alignment, inputs: &[Arg]) -> Val {
        let inputs = inputs.iter().map(|&a| self.operand(a)).collect();
        let output = self.fresh("keccak", IrType::Bytes32);
        self.instructions.push(Instruction::Keccak256 {
            alignment,
            inputs,
            output: self.name(output),
        });
        output
    }

    /// Hash native field elements to a Jubjub point.
    pub fn hash_to_curve(&mut self, inputs: &[Arg]) -> Val {
        let inputs = self.natives(inputs, "hash_to_curve");
        let output = self.fresh("h2c", IrType::JubjubPoint);
        self.instructions.push(Instruction::HashToCurve {
            inputs,
            output: self.name(output),
        });
        output
    }

    // --- elliptic-curve operations ------------------------------------------------

    /// Multiply a point by a scalar of its curve.
    pub fn ec_mul(&mut self, point: impl Into<Arg>, scalar: impl Into<Arg>) -> Val {
        let (point, scalar) = (point.into(), scalar.into());
        let pt = self.ty(point);
        let expected_scalar = scalar_type(&pt)
            .unwrap_or_else(|| panic!("ec_mul: operand must be a point, got {pt:?}"));
        let st = self.ty(scalar);
        assert!(
            st == expected_scalar,
            "ec_mul: scalar must be {expected_scalar:?} for {pt:?}, got {st:?}"
        );
        let output = self.fresh("ecmul", pt);
        self.instructions.push(Instruction::EcMul {
            a: self.operand(point),
            scalar: self.operand(scalar),
            output: self.name(output),
        });
        output
    }

    /// Multiply the curve generator matching the scalar's type. The ir.rs
    /// doc comment says JubjubScalar only, but the VM dispatches on the
    /// scalar type and also supports Secp256k1Scalar (ir_vm.rs:559-568) —
    /// which compactc relies on for `secp256k1EcdsaVerify`.
    pub fn ec_mul_generator(&mut self, scalar: impl Into<Arg>) -> Val {
        let scalar = scalar.into();
        let point_ty = match self.ty(scalar) {
            IrType::JubjubScalar => IrType::JubjubPoint,
            IrType::Secp256k1Scalar => IrType::Secp256k1Point,
            t => panic!("ec_mul_generator: operand must be a Jubjub or Secp256k1 scalar, got {t:?}"),
        };
        let output = self.fresh("ecgen", point_ty);
        self.instructions.push(Instruction::EcMulGenerator {
            scalar: self.operand(scalar),
            output: self.name(output),
        });
        output
    }

    /// The affine coordinates `(x, y)` of a point. Unsatisfiable for the
    /// identity on Weierstrass curves.
    pub fn into_coordinates(&mut self, point: impl Into<Arg>) -> (Val, Val) {
        let point = point.into();
        let pt = self.ty(point);
        let coord = coordinate_type(&pt)
            .unwrap_or_else(|| panic!("into_coordinates: operand must be a point, got {pt:?}"));
        let x = self.fresh("x", coord.clone());
        let y = self.fresh("y", coord);
        self.instructions.push(Instruction::IntoCoordinates {
            point: self.operand(point),
            outputs: (self.name(x), self.name(y)),
        });
        (x, y)
    }

    /// Reconstruct a point of `point_ty` from affine coordinates. Cannot
    /// build the identity on Weierstrass curves.
    pub fn from_coordinates(
        &mut self,
        point_ty: IrType,
        x: impl Into<Arg>,
        y: impl Into<Arg>,
    ) -> Val {
        let (x, y) = (x.into(), y.into());
        let coord = coordinate_type(&point_ty).unwrap_or_else(|| {
            panic!("from_coordinates: target must be a point type, got {point_ty:?}")
        });
        for arg in [x, y] {
            let ty = self.ty(arg);
            assert!(
                ty == coord,
                "from_coordinates: coordinate must be {coord:?} for {point_ty:?}, got {ty:?}"
            );
        }
        let output = self.fresh("pt", point_ty);
        self.instructions.push(Instruction::FromCoordinates {
            inputs: (self.operand(x), self.operand(y)),
            output: self.name(output),
        });
        output
    }

    // --- Bytes<32> conversions -------------------------------------------------

    /// The canonical little-endian 32-byte form of a prime-field element.
    pub fn into_bytes32(&mut self, input: impl Into<Arg>) -> Val {
        let input = input.into();
        self.expect(
            input,
            supports_bytes32_conversion,
            "a prime-field element",
            "into_bytes32",
        );
        let output = self.fresh("bytes", IrType::Bytes32);
        self.instructions.push(Instruction::IntoBytes32 {
            input: self.operand(input),
            output: self.name(output),
        });
        output
    }

    /// A prime-field element of `ty` from its (possibly non-canonical,
    /// reduced mod the field order) little-endian 32-byte form.
    pub fn from_bytes32(&mut self, bytes: impl Into<Arg>, ty: IrType) -> Val {
        let bytes = bytes.into();
        self.expect(
            bytes,
            |t| matches!(t, IrType::Bytes32),
            "Bytes<32>",
            "from_bytes32",
        );
        assert!(
            supports_bytes32_conversion(&ty),
            "from_bytes32: target must be a prime-field type, got {ty:?}"
        );
        let output = self.fresh("field", ty.clone());
        self.instructions.push(Instruction::FromBytes32 {
            bytes: self.operand(bytes),
            val_t: ty,
            output: self.name(output),
        });
        output
    }

    /// Reverse the byte order of a `Bytes<32>` value.
    pub fn reverse_bytes(&mut self, bytes: impl Into<Arg>) -> Val {
        let bytes = bytes.into();
        self.expect(
            bytes,
            |t| matches!(t, IrType::Bytes32),
            "Bytes<32>",
            "reverse_bytes",
        );
        let output = self.fresh("rev", IrType::Bytes32);
        self.instructions.push(Instruction::ReverseBytes {
            bytes: self.operand(bytes),
            output: self.name(output),
        });
        output
    }

    /// Decompose `Bytes<32>` into `(low, high)` native elements: low = the
    /// first 31 bytes little-endian, high = the last byte. (Compact's field-
    /// element view of `Bytes<32>`.)
    pub fn bytes32_into_low_high(&mut self, bytes: impl Into<Arg>) -> (Val, Val) {
        let bytes = bytes.into();
        self.expect(
            bytes,
            |t| matches!(t, IrType::Bytes32),
            "Bytes<32>",
            "bytes32_into_low_high",
        );
        let low = self.fresh("low", IrType::Native);
        let high = self.fresh("high", IrType::Native);
        self.instructions.push(Instruction::Bytes32IntoLowHigh {
            bytes: self.operand(bytes),
            outputs: (self.name(low), self.name(high)),
        });
        (low, high)
    }

    /// Compose `Bytes<32>` from `(low, high)` native elements; `low` must fit
    /// in 31 bytes and `high` in 1.
    pub fn bytes32_from_low_high(&mut self, low: impl Into<Arg>, high: impl Into<Arg>) -> Val {
        let (low, high) = (low.into(), high.into());
        self.expect_native(low, "bytes32_from_low_high");
        self.expect_native(high, "bytes32_from_low_high");
        let output = self.fresh("bytes", IrType::Bytes32);
        self.instructions.push(Instruction::Bytes32FromLowHigh {
            inputs: (self.operand(low), self.operand(high)),
            output: self.name(output),
        });
        output
    }

    /// A `JubjubScalar` from a native element (transitional upstream
    /// instruction, pending a BigUint type).
    pub fn jubjub_scalar_from_native(&mut self, native: impl Into<Arg>) -> Val {
        let native = native.into();
        self.expect_native(native, "jubjub_scalar_from_native");
        let output = self.fresh("jscalar", IrType::JubjubScalar);
        self.instructions.push(Instruction::JubjubScalarFromNative {
            native: self.operand(native),
            output: self.name(output),
        });
        output
    }

    /// Encode a value as its raw native-element representation
    /// ([`IrType::encoded_len`] outputs; e.g. `Bytes<32>` → low, high).
    pub fn encode(&mut self, input: impl Into<Arg>) -> Vec<Val> {
        let input = input.into();
        let len = self.ty(input).encoded_len();
        let outputs: Vec<Val> = (0..len).map(|_| self.fresh("enc", IrType::Native)).collect();
        self.instructions.push(Instruction::Encode {
            input: self.operand(input),
            outputs: outputs.iter().map(|&v| self.name(v)).collect(),
        });
        outputs
    }

    // --- transcript inputs ---------------------------------------------------------

    /// Read the next private-transcript (witness) value as type `ty`. If
    /// `guard` is given and false at runtime, yields a default without
    /// consuming the transcript.
    pub fn private_input(&mut self, ty: IrType, guard: Option<Arg>) -> Val {
        if let Some(g) = guard {
            self.expect_native(g, "private_input guard");
        }
        let guard = guard.map(|g| self.operand(g));
        let output = self.fresh("w", ty.clone());
        self.instructions.push(Instruction::PrivateInput {
            guard,
            val_t: ty,
            output: self.name(output),
        });
        output
    }

    /// Read the next public-transcript output value as type `ty`, guarded
    /// like [`Builder3::private_input`].
    pub fn public_input(&mut self, ty: IrType, guard: Option<Arg>) -> Val {
        if let Some(g) = guard {
            self.expect_native(g, "public_input guard");
        }
        let guard = guard.map(|g| self.operand(g));
        let output = self.fresh("pi", ty.clone());
        self.instructions.push(Instruction::PublicInput {
            guard,
            val_t: ty,
            output: self.name(output),
        });
        output
    }

    // --- constraints and effects (no value produced) ------------------------------

    /// Constrain `cond` (must hold 0 or 1) to be 1.
    pub fn assert(&mut self, cond: impl Into<Arg>) {
        let cond = cond.into();
        self.expect_native(cond, "assert");
        self.instructions.push(Instruction::Assert {
            cond: self.operand(cond),
        });
    }

    pub fn constrain_eq(&mut self, a: impl Into<Arg>, b: impl Into<Arg>) {
        let (a, b) = (a.into(), b.into());
        self.expect(a, supports_eq_add, "a field element or point", "constrain_eq");
        self.expect(b, supports_eq_add, "a field element or point", "constrain_eq");
        self.expect_same(a, b, "constrain_eq");
        self.instructions.push(Instruction::ConstrainEq {
            a: self.operand(a),
            b: self.operand(b),
        });
    }

    pub fn constrain_bits(&mut self, val: impl Into<Arg>, bits: u32) {
        let val = val.into();
        self.expect_native(val, "constrain_bits");
        self.instructions.push(Instruction::ConstrainBits {
            val: self.operand(val),
            bits,
        });
    }

    pub fn constrain_to_boolean(&mut self, val: impl Into<Arg>) {
        let val = val.into();
        self.expect_native(val, "constrain_to_boolean");
        self.instructions.push(Instruction::ConstrainToBoolean {
            val: self.operand(val),
        });
    }

    /// Declare native public inputs under a guard: v3's public-input block
    /// (v2's DeclarePubInput + PiSkip collapsed into one instruction). If
    /// `guard` is false at runtime the inputs become zeros, enforced
    /// in-circuit.
    pub fn impact(&mut self, guard: impl Into<Arg>, inputs: &[Arg]) {
        let guard = guard.into();
        self.expect_native(guard, "impact guard");
        let inputs = self.natives(inputs, "impact");
        self.instructions.push(Instruction::Impact {
            guard: self.operand(guard),
            inputs,
        });
    }

    /// Return values from the circuit, typed against the output signature.
    /// At most one Output terminator per circuit.
    pub fn output(&mut self, vals: &[Arg]) {
        assert!(
            self.outputs.is_none(),
            "output() already called: a v3 circuit has one Output terminator"
        );
        self.outputs = Some(vals.iter().map(|&v| self.ty(v)).collect());
        let vals = vals.iter().map(|&v| self.operand(v)).collect();
        self.instructions.push(Instruction::Output { vals });
    }

    // --- finishing --------------------------------------------------------------------

    /// Number of instructions so far.
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Number of circuit-argument slots declared so far.
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Run [`passes::dedup_range_constraints`] in [`Builder3::finish`].
    ///
    /// OFF by default and left off by every shipped circuit: the pass makes
    /// us strictly more deduplicated than compactc, which re-emits its own
    /// range constraints, so turning it on costs the instruction-for-
    /// instruction differentials (notes/ir-passes.org §1 — the opt profile,
    /// with M10's warrant).
    ///
    /// What it buys where it is on: a gadget can constrain its own inputs
    /// instead of documenting a precondition, because the constraint a
    /// caller already emitted is removed rather than paid for twice (two
    /// rows, the most expensive redundancy measured — §0b).
    pub fn dedup_range_constraints(&mut self, on: bool) {
        self.dedup_constraints = on;
    }

    /// Finish into a v3 [`IrSource`].
    ///
    /// FOLD FIRST, THEN DROP TRUE ASSERTS, THEN DEDUP, and the order is not
    /// arbitrary. The fold
    /// substitutes immediates into operand positions, so a constraint on a
    /// named constant becomes a constraint on an IMMEDIATE — which the dedup
    /// pass deliberately leaves alone, having no wire to key on. Running the
    /// fold first means the dedup pass sees the operands the circuit will
    /// actually ship: every decision it makes is about a name that survives.
    /// The other order would have it key on identifiers the fold is about to
    /// remove, and reach a different (weaker) answer for the same circuit.
    ///
    /// The reverse dependency does not exist: the dedup pass only ever
    /// DELETES constraints, which bind no names and produce no values, so it
    /// cannot invalidate anything the fold established.
    ///
    /// [`passes::drop_true_asserts`] sits between them, and its position is
    /// forced by the same argument as the dedup's: `c.assert(c.constant(1))`
    /// is `copy %k = 1; assert %k`, and only the fold turns that into
    /// `assert 1`, which is the shape the rule deletes. Before the fold it
    /// would see nothing. It is ALWAYS ON, like the fold and unlike the
    /// dedup: it removes a check that holds on every preimage, so `run` is
    /// preserved exactly (`MinocrabProofs.AssertIr.dropTrueAsserts_preserves_run`).
    /// It fires on the typed EVM-call API's constant-true outcome rule
    /// (notes/evm-calls.org §3.2): the `assert(imm 1)` in
    /// `erc20_vault_pending::{complete_swap, complete_supply,
    /// complete_redeem}` (notes/ir-passes.org §13).
    ///
    /// EVERY PASS HERE IS A FILTER — it deletes instructions, never inserts
    /// or reorders — and builds its map through `passes::retain_kept`, which
    /// is what lets [`Builder3::finish_kept`] say where each built
    /// instruction went. A pass added here must be one too.
    pub fn finish(self, communications_commitment: bool) -> IrSource {
        self.finish_kept(communications_commitment).0
    }

    /// [`Builder3::finish`], and where every built instruction went.
    ///
    /// The passes above DELETE instructions, so an index taken while
    /// building (`self.len()` at some point) names a different instruction,
    /// or none, in the finished stream. The returned [`passes::Kept`] maps a
    /// build-time index onto the finished one: `position` for an
    /// instruction, `boundary` for the end of a half-open span. It is the
    /// composition of each pass's own map, in the order the passes ran.
    pub fn finish_kept(self, communications_commitment: bool) -> (IrSource, passes::Kept) {
        let built = self.instructions.len();
        #[cfg(debug_assertions)]
        let built_stream = self.instructions.clone();
        let (instructions, kept) = passes::fold_immediate_copies_kept(self.instructions);
        let (instructions, dropped) = passes::drop_true_asserts_kept(instructions);
        let kept = kept.compose(&dropped);
        let (instructions, kept) = if self.dedup_constraints {
            let (instructions, deduped) = passes::dedup_range_constraints_kept(instructions);
            (instructions, kept.compose(&deduped))
        } else {
            (instructions, kept)
        };
        // The map covers exactly the stream that was built and the one that
        // ships: a pass run above without composing its map fails here.
        assert_eq!(kept.input_len(), built, "finish_kept: the map must start at the built stream");
        assert_eq!(
            kept.output_len(),
            instructions.len(),
            "finish_kept: compose every pass's map, in the order the passes run"
        );
        #[cfg(debug_assertions)]
        passes::check_kept(&built_stream, &instructions, &kept);
        let ir = IrSource {
            version: Default::default(),
            inputs: self.inputs,
            outputs: self.outputs.unwrap_or_default(),
            do_communications_commitment: communications_commitment,
            instructions: Arc::new(instructions),
        };
        (ir, kept)
    }
}
