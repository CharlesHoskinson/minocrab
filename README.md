# MinoCrab

Rust eDSL for Midnight contracts, usable instead of Compact.

This whole project is vibe coded. If you use it for Midnight applications that do stuff with money, your users will likely lose it, and neither you nor I will know why.

That said, it is a direct port of the Compact compiler with millions of tests checking compliance. Evaluating it seriously? Start with:

- [VERIFICATION.md](VERIFICATION.md) — how we check that this compiler behaves correctly.
- [BENCHMARK.md](BENCHMARK.md) — the seventeen-circuit vault against compactc, proving the identical statement: request circuits one to three `k` levels lower (prove −44..−81%), the ECDSA-floored settles at parity, the singleton −95..−97%.

## Why use this

**More errors caught at compile time.** A `Wire<Private>` cannot reach a public output without `disclose(w, label)`, and the label must appear in the circuit's signature; a generated test enforces that and caught four real undeclared disclosures ([disclose.rs](crates/minocrab/src/v3/disclose.rs)). Subtraction emits its underflow guard. A guarded-off read must say what its default means. A literal outside its operand's bound doesn't build. Argument types *are* the range constraints: `Uint<64>` is `assert_bits(w, 64)`, from compactc's own table ([v3_leaves.rs](crates/minocrab-std/tests/v3_leaves.rs)).

**Rust tooling for testing and verification.** Circuits run natively under `cargo test` ([minocrab-sim](crates/minocrab-sim/src/lib.rs)). That makes a reference model affordable: every vault circuit's run is replayed through Midnight's reference VM against a modelled pre-state, with the guard failures both artifacts must reject and a tamper sweep over every transcript and witness element ([erc20_vault_differential.rs](crates/minocrab-contracts/tests/erc20_vault_differential.rs)); the Pending lineage keeps an eighteen-property spec harness and its own executor replay ([erc20_vault_pending_spec.rs](crates/minocrab-contracts/tests/erc20_vault_pending_spec.rs), [executor_vault.rs](crates/minocrab-contracts/tests/executor_vault.rs)); and a leakage inventory is generated from the ZKIR itself ([leakage_inventory.rs](crates/minocrab-contracts/tests/leakage_inventory.rs)). Every ported circuit is differential-tested against compactc's artifact ([porting kit](#porting-kit)); `(k, rows)` and the interfaces of all 226 circuits are frozen, so drift is a test failure ([row_snapshot.rs](crates/minocrab-contracts/tests/row_snapshot.rs)). The property harness and adversarial sweeps of the seventeen-circuit vault retired with it (M44); their flush-pattern successors are the milestone's open rung F.

**Direct ZKIR emission.** Low-level instruction selection: native byte instructions instead of explode/rebuild chains, one-block hashes where the preimage fits, Poseidon where the spec permits it. Rows −12..−86% on the vault, prove time −44..−81% wherever a circuit is not floored by protocol-pinned crypto ([BENCHMARK.md](BENCHMARK.md)).

**Standard serialisation, or your own.** Records are a [Borsh](https://borsh.io) subset: a published spec with implementations in many languages, so both ends of the wire are auditable separately. Compact's FAB encoding stays for compatibility, and Compact contract interfaces can be imported. All a standard `Serialize` implementation.

**It's all just Rust.** cargo, crates.io, rust-analyzer, `#[test]`, modules and visibility. Circuit families are const generics, monomorphized by rustc ([notes/const-generics.org](notes/const-generics.org)). A deployed contract imports as a typed crate, checked against the callee's compiled artifact ([interface-gen](crates/minocrab-interface-gen)). Macros too, if that's your cup of tea.

## Side by side

`erc20-vault`'s `deposit`, from the sig-net corpus:

```compact
struct DepositRequest {
  erc20Address: Bytes<20>;
  amount: Uint<128>;
}

export circuit deposit(
  evmNonce: Uint<64>,
  gasLimit: Uint<64>,
  maxFeePerGas: Uint<128>,
  maxPriorityFeePerGas: Uint<128>,
  keyVersion: Uint<8>,
  depositRequest: DepositRequest
): [] {
  assert(depositRequest.amount > 0 as Uint<128>, "Amount must be positive");
  const caller = disclose(userCommitment(callerSecretKey()));
  // ... compose calldata, tx params, request ...
  const requestId = disclose(calculateRequestId<EvmType2TxParams<2, 0, 0>, 34, 34>(request));
  assert(!signBidirectionalEventMap.member(requestId), "Request already exists");
  signBidirectionalEventMap.insert(requestId, disclose(request));
}
```

The same circuit on the typed Sig Network API, abridged from [erc20_vault_pending.rs](crates/minocrab-contracts/src/erc20_vault_pending.rs) (the instruction-for-instruction port is `erc20_vault.rs`):

```rust
#[derive(CircuitArg)]
struct DepositRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
}

#[circuit]
pub fn deposit(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    gas_limit: Uint<64>,
    max_fee_per_gas: Uint<128>,
    max_priority_fee_per_gas: Uint<128>,
    key_version: Uint<8>,
    deposit_request: DepositRequest,
) -> Discloses<(DepositorCommitment, DepositedErc20, DepositedAmount, Requested)> {
    c.assert(deposit_request.amount.gt(0u64));

    let sk = common::witness_sk(c);
    let caller = common::commitment_transient(c, &sk).disclose_as::<DepositorCommitment>(c);
    let erc20 = deposit_request.erc20_address.disclose_as::<DepositedErc20>(c);
    let amount = deposit_request.amount.field().disclose_as::<DepositedAmount>(c);

    // transfer(vaultEvmAddress, amount) on the token. The selector, ABI words,
    // request id, freshness check, record insert and signer call all come from
    // the slot's type, `Pending<Deposit, DepositEnv, VAULT_WORDS>`.
    VAULT.deposits.request_with(
        c,
        |c| Contract::<Erc20>::from_address(c, deposit_request.erc20_address),
        (
            |c: &mut Circuit3| cell_address(c, &VAULT.vault_evm_address),
            |_c: &mut Circuit3| deposit_request.amount,
        ),
        Envelope::caller(max_priority_fee_per_gas, max_fee_per_gas, gas_limit),
        key_version,
        evm_nonce,
        |_c| (common::SigningPath::from(caller.private()), ()),
        |_c, _id, ()| DepositEnv { depositor: caller, erc20, amount: Uint::from_field_unchecked(amount) },
    );
    Discloses::of(())
}
```

The return type is the disclosure manifest; a generated test fails if the circuit discloses anything not in it. The direct port is PI-equal to compactc's artifact on every circuit ([erc20_vault_differential.rs](crates/minocrab-contracts/tests/erc20_vault_differential.rs)); the `Pending` version is gated on its block layout, its cost against the port, an eighteen-property spec harness and a round trip through the MPC's own reader ([erc20_vault_pending.rs](crates/minocrab-contracts/tests/erc20_vault_pending.rs), [signet_flow.rs](crates/minocrab-contracts/tests/signet_flow.rs)).

## Feature by feature

**Argument struct**

```compact
struct DepositRequest {
  erc20Address: Bytes<20>;
  amount: Uint<128>;
}
```
```rust
#[derive(CircuitArg)]
struct DepositRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
}
```

**Circuit** — the return type is the disclosure manifest, enforced by a generated test.

```compact
export circuit deposit(evmNonce: Uint<64>, gasLimit: Uint<64>): [] { /* ... */ }
```
```rust
#[circuit]
pub fn deposit(c: &mut Circuit3, evm_nonce: Uint<64>, gas_limit: Uint<64>) -> Discloses<()> { /* ... */ }
```

**Cost budget** — `max_k` is the circuit's ceiling in `k` (log2 of the proving-table rows: proving key, prover RAM, wall clock). A generated test prices the circuit with Midnight's own cost model and fails when it goes over. Compact has no equivalent.

```compact
// no equivalent: cost is discovered by compiling and looking
```
```rust
#[circuit(max_k = 14)]
pub fn deposit(c: &mut Circuit3, evm_nonce: Uint<64>, gas_limit: Uint<64>) { /* ... */ }
```

**Loop** — plain Rust over any slice, `Vec` or iterator, unrolled by rustc. Compact has `for` over a range or vector plus `map`/`fold` and nothing else; `while`, `break`, early return, iterator adapters and host-side data structures are Rust's alone. Neither side can loop on a wire: ZKIR has no loop instruction, so the length is fixed once the circuit is built.

```compact
circuit sum<#N>(v: Vector<N, Uint<64>>): Uint<64> {
  return fold((acc: Field, x: Uint<64>) => acc + (x as Field), 0 as Field, v) as Uint<64>;
}
```
```rust
fn sum(c: &mut Circuit3, v: &[Uint<64>]) -> Uint<64> {
    let mut acc = c.constant(0u64).private();
    for &x in v {
        acc = c.add(acc, x.field());
    }
    Uint::from_field_checked(c, acc)
}
```

**Variable-length argument** — `Bounded<T, MAX>` is a length limb and a contiguous prefix; `NonEmpty<T, REST>` is a head plus a bounded tail, so "at least one" is a type, not an assert. The length is range-checked by the argument constraint (compactc's own table, at `Uint<0..MAX+1>`), and `fold` / `for_each` own the guard: a dead slot's ledger ops are skipped on chain and its step never reaches the carried state. Compact's circuits have only the fixed `Vector<N, T>`; variable length is hand-rolled as a vector plus a length or a `Maybe` per slot (the corpus's `Vector<5000, Maybe<…>>`), the ledger `List` cannot be iterated from a circuit, and non-emptiness is a runtime assert. Proof cost is `MAX` either way; the ledger applies `len` steps ([v3_vector.rs](crates/minocrab-std/tests/v3_vector.rs)).

```compact
circuit flush(keys: Vector<4, Maybe<Uint<64>>>): [] {
  assert(keys[0].is_some, "empty flush");
  for (const k of keys) {
    if (k.is_some) { queue.remove(disclose(k.value)); }   // the select on any carried state is yours to write
  }
}
```
```rust
#[circuit]
fn flush(c: &mut Circuit3, keys: NonEmpty<Uint<64>, 3>) -> Discloses<(FlushKeys,)> {
    let keys = keys.disclose_as::<FlushKeys>(c);
    keys.for_each(c, |c, k| QUEUE.remove(c, k));            // guarded per slot, the head unconditionally
    Discloses::of(())
}
```

**Blind ledger update** — inline is the read set, the hook is the write program. Every inline ledger read is a `popeq`: an assumption the landing validates, which a landed transaction can make stale. A `Hook` is a program the ledger runs *after* the body on whatever it holds then — `add` / `sub` / `max` / `min` / `and` / `or` on a cell, `copy` of a cell into a map entry the circuit never reads, `move_entry`, `if_absent` / `if_below` / `if_unset` branches — and it embeds no public input, so nothing can stale it and it cannot tell the circuit anything. Attached with `c.then(hook)`, emitted in attachment order under the guard of the `when` it was attached in. The accumulator behind a contention-free outbox (M41) is one: `(Add, Max)` over `(nonce, last_seen)`, one cell and one snapshot map per component. And the read side is typed: every inline read returns `Assumed<T>`, which the proof uses as `T` and the ledger refuses to store until `.stale(c)` names the assumption — so a read-modify-write says so where it happens, and a value *computed* from a read is caught at the ledger boundary at build time, naming the read. Compact compiles every ledger read to a `popeq` except `Counter.increment`; it has no construct that moves a ledger value to another slot without reading it into the circuit (`m.insert(k, cell)` reads `cell` first) and no ledger-side compare-and-select (`Counter.lessThan` is a read). Gated on Midnight's on-chain VM, not on a compactc artifact ([v3_hook.rs](crates/minocrab-std/tests/v3_hook.rs), [v3_blind.rs](crates/minocrab-std/tests/v3_blind.rs)); four to twelve Impact ops per method, zero read rows.

```compact
// no equivalent: nonces.insert(k, nonce) reads `nonce` (a popeq) before it inserts,
// so two calls proven against one state cannot both land
```
```rust
c.then(Hook::new()
    .add(&NONCE, 1u64)                 // idxp; push 1; add; insc — no popeq
    .copy(&NONCE, &SNAPSHOT, k)        // idxp; push k; dup 3; idx; ins 1; insc — no popeq
    .max(&SEEN, height));              // the kernel-mint compare-and-select, ledger side

let seen = SEEN_AT.lookup(c, &k);      // Assumed<Uint<64, Public>>: the proof may compare it,
c.assert(height.gt(seen));             // the ledger will not store it —
OTHER.write(c, &seen);                 // error: write `.stale(c)` to name the assumption
```

**Assert** — the comparison width comes from the operand's type, never typed at the call site.

```compact
assert(depositRequest.amount > 0 as Uint<128>, "Amount must be positive");
```
```rust
c.assert(deposit_request.amount.gt(0u64).message("Amount must be positive"));
```

**Subtraction** — compactc inserts `assert(a >= b)` before every `-`; `sub` emits the same guard, in the same order, at the same width, byte-identical against compactc's artifact.

```compact
const change = amountInMaximum - amountIn;
```
```rust
let change = amount_in_max.sub(c, amount_in);
```

**Disclose** — the label must appear in the circuit's return type, or a generated test fails.

```compact
const caller = disclose(userCommitment(callerSecretKey()));
```
```rust
let caller = commitment.disclose_as::<DepositorCommitment>(c);
```

**Ledger cell** — the FAB atoms come from the slot's type; nobody writes an atom list at a call site.

```compact
export ledger vaultEvmAddress: Bytes<20>;
// ...
const addr = vaultEvmAddress;
```
```rust
#[derive(Ledger)]
struct Vault { vault_evm_address: LedgerCell<Bytes<20, Public>>, /* ... */ }
// ...
let addr = VAULT.vault_evm_address.read(c);
```

**Ledger map** — one Impact op per method, `c` visible because a ledger operation is a cost.

```compact
signBidirectionalEventMap.insert(requestId, disclose(request));
assert(!signBidirectionalEventMap.member(requestId), "Request already exists");
```
```rust
VAULT.sign_bidirectional_event_map.insert(c, &request_id, &record);
let exists = VAULT.sign_bidirectional_event_map.member(c, &request_id);
```

**Conditional effects** — reads, witnesses and assertions inside the scope inherit the guard.

```compact
if (cond) { /* ... */ }
```
```rust
c.when(cond, |c| { /* ... */ });
```

**Conditional value** — returns a `#[must_use]` `Selected<T>`: every arm was paid for.

```compact
const x = cond ? a : b;
```
```rust
let x = c.when_value(cond, |c| a).otherwise(b);
```

**Bounded integer** — compares at compactc's width; a literal above the bound is rejected at build time; `add`/`mul` carry the result bound in the type; `narrow` emits a range check at the seam, ~BITS/4 rows, stated.

```compact
const requestNonce = signetRequestNonce as Uint<64>;   // Uint<0..n> arithmetic tracked by the compiler
```
```rust
let sum = a.add::<499, 200>(c, b);   // BoundedUint<300> + BoundedUint<200> -> BoundedUint<499>
let small = sum.narrow::<8>(c);      // the CHECKED downcast
```

**Cross-contract call** — an `#[interface]`-generated typed method; the callee's disclosures must be named in *your* declaration.

```compact
SignetSigner.signBidirectional(requestId, notification);
```
```rust
SIGNET.sign_bidirectional(c, &request_id, &notification);
```

**Witness** — inside `c.when` a witness does not consume the private transcript on the untaken branch.

```compact
witness callerSecretKey(): Bytes<32>;
```
```rust
let sk = common::witness_sk(c);
```

**Opaque** — the TypeScript type is a Rust type parameter.

```compact
maybeStr: Opaque<"string">
```
```rust
maybe_str: Opaque<Str>   // Str: TsType
```

**Hash** — or `SHA-256(borsh(value))` in one instruction through the Borsh layer.

```compact
persistentHash<Vector<2, Bytes<32>>>([a, b])
```
```rust
c.persistent_hash(alignment, &[a, b]);
borsh::persistent_hash(c, &value)   // digest of the canonical Borsh encoding
```

Subtraction adds safety on top of the platform's own: the underflow guard cannot be forgotten. Every such addition costs zero rows or a stated number, never a hidden one.

## Cross-contract calls

```toml
[dependencies]
signet-signer-interface = { path = "../signet-signer-interface" }
```

```rust
use signet_signer_interface::{notification::construct_notification_v1, SignetSigner};

let signer = SignetSigner::at_field(SIGNET_SIGNER).pin(c, one);
let me = ContractAddress::from_limbs(kernel_self(c, one));
let notification = construct_notification_v1::<Public>(c, &me.bytes(), 1, notify_path);
signer.sign_bidirectional(c, one, *request_id, notification);
```

The interface crate is a bodyless trait, one item per callee circuit:

```rust
#[interface]
pub trait SignetSigner {
    fn sign_bidirectional(
        request_id: RequestId<Public>,
        notification: SignBidirectionalEventNotification<Public>,
    );
    // respond, respondBidirectional
}
```

- The call line is the whole desugar: argument flattening, result-limb witnesses, communications commitment, effects claim
- Entry-point hashes and commitment layout follow upstream's own derivation
- Every parameter is `Public`: passing a value cross-contract discloses it, so a forgotten `disclose()` is a compile error
- No address in the crate: `at_field(index)` names a sealed ledger cell, `at(address)` takes one as data
- Each crate commits the callee's artifact plus a hash pin and checks slots, constraints and the compiled `.zkir` prefix against it; a mutation suite proves the checks bite, including a forged circuit with a correct manifest

Limit: the circuit binds neither the entry point nor the argument types unless asked. `minocrab_ledger::bind_entry_points(c)` is the opt-in hardened mode: every typed call then constrains the entry-point hash to the declared circuit's. Argument types stay unbound.

## Cross-chain calls

A Sig Network cross-chain call is one operation across two Midnight transactions with an MPC round trip between: a **request** circuit files the EVM transaction and notifies the Signet singleton; the MPC signs it with the contract's derived key, executes it and attests the output back; a **complete** circuit verifies the attestation and finishes, or a **refund** circuit does when the call did not succeed. The CALL is a Rust type ([evm.rs](crates/minocrab-contracts/src/evm.rs)) and the ledger slot is typed by it ([evm_flow.rs](crates/minocrab-contracts/src/evm_flow.rs)): selector, ABI words, response type, gas envelope, signing path and notification path all derive from the one thing the author writes down.

A whole treasury that sends an ERC-20 `transfer(to, amount)` from its derived EVM account, compiled and tested ([treasury.rs](crates/minocrab-contracts/src/treasury.rs)):

```rust
/// The library's `erc20::Transfer`, filed under response kind 1.
pub type Transfer = Kinded<erc20::Transfer, 1>;

#[derive(Ledger)]
pub struct Treasury {
    /// Signer, MPC key, request nonce, caip2 id, chain id.
    pub signet: Signet,
    /// Every in-flight transfer, the caller committed into each environment.
    pub transfers: Pending<Transfer, Owned<Amount>, 2>,
}

#[contract]
impl Treasury {
    #[circuit]
    pub fn send(
        c: &mut Circuit3,
        evm_nonce: Uint<64>,
        key_version: Uint<8>,
        token: Contract<Erc20>,
        to: Bytes<20>,
        amount: Uint<64>,
    ) -> Discloses<(SentAmount, OwnerCommitment, Requested)> {
        let sent = amount.field().disclose_as::<SentAmount>(c);
        TREASURY.transfers.request_owned::<OwnerCommitment>(
            c,
            token,
            (to, amount.widen::<128>()),
            key_version,
            evm_nonce,
            |_, _| Amount { amount: Uint::from_field_unchecked(sent) },
        );
        Discloses::of(())
    }

    /// Anyone may call: the attestation is the gate. A mined `transfer`
    /// that returned `false` cannot reach here — `complete` asserts the
    /// call's own success rule.
    #[circuit]
    pub fn complete(c: &mut Circuit3, ticket: Succeeded<Transfer>) -> Discloses<Settled> {
        let outcome = TREASURY.transfers.complete(c, ticket);
        let _amount = outcome.env.inner.amount;
        Discloses::of(())
    }

    /// Only the original caller: a fresh witness opens the commitment.
    #[circuit]
    pub fn refund(c: &mut Circuit3, ticket: Failed<Transfer>) -> Discloses<(Settled, RefundRecipient)> {
        let (_owner, Amount { amount: _amount }, _flag) =
            TREASURY.transfers.refund_to_owner::<RefundRecipient>(c, ticket);
        Discloses::of(())
    }
}
```

`erc20::Transfer` is the CALL: the Solidity facts (`transfer`, `(address, uint256)`, a `bool` return, the `Erc20` interface, a gas limit, the success rule). One module per interface under [evm/](crates/minocrab-contracts/src/evm). `Transfer` above is the FILING: the same call plus a deployment's response kind byte and the record's return name. The vault files `erc20::Transfer` under two kinds, deposit and withdrawal, and its seventeen circuits are all on this API ([erc20_vault_pending.rs](crates/minocrab-contracts/src/erc20_vault_pending.rs)).

| Interface | Calls | Words | Return |
|---|---|---|---|
| `Erc20` | `transfer`, `approve`, `transferFrom`, `increaseAllowance`, `decreaseAllowance` | 2–3 static | `bool`, the flag is the success rule |
| | ERC-2612 `permit` | 7 static | none |
| `Weth` (IS an `Erc20`) | `deposit()` payable, `withdraw` | 0–1 static | none |
| `UsdtLike` (sibling of `Erc20`) | `transfer`, `approve`, `transferFrom` | 2–3 static | none — mined is success |
| `Erc4626` (IS an `Erc20`) | `deposit`, `mint`, `withdraw`, `redeem` | 2–3 static | `uint256` |
| `UniswapV3Router` (= SwapRouter02) | `exactInputSingle`, `exactOutputSingle` | 7 static (one struct) | `uint256` |
| `AaveV3Pool` | `supply`, `withdraw`, `borrow`, `repay` | 3–5 static | none / `uint256` |
| | `supplyWithPermit` | 8 static | none |
| `Erc721` (sibling of `Erc20`) | `transferFrom`, `approve`, `setApprovalForAll` | 2–3 static | none |

Every row is STATIC, which is what lets the ledger record be fixed-width; dynamic ABI types (`bytes`, `string`, `T[]`) wait for a consumer. Every selector and word is pinned against alloy's encoder ([evm_alloy_oracle.rs](crates/minocrab-contracts/tests/evm_alloy_oracle.rs)) and, where the deployed vault has one, against compactc's calldata ([evm_abi.rs](crates/minocrab-contracts/tests/evm_abi.rs)). `UsdtLike` and `Erc721` are deliberate siblings of `Erc20`: their calls hash to the same selectors on the same calldata but return nothing, so the callee's interface is the only thing that tells them apart, and both directions of that confusion are compile errors.

What the types do:

- **Mis-pairing does not compile.** A `Succeeded<Transfer>` settles the `transfers` slot and no other; a `Failed` cannot be handed to `complete`; an argument tuple in the wrong order is a type error; a `WORDS` that is not the call's word count, or two slots of one block at one kind, is `error[E0080]`. Twenty-two such refusals are doc-tests that must fail to compile.
- **A call goes only where its interface does.** `request` accepts a callee only when its interface `Extends` the call's own: `erc20::Transfer` on a `Contract<UniswapV3Router>` is a missing impl; `erc20::Approve` on a `Contract<Erc4626>` compiles. The marker costs no instruction.
- **The outcome picks the circuit.** `complete` asserts the call's success rule; `refund` takes both non-successes. The deployed vault's Gap 2 (a refund branch inside the completion) has no method on this API.
- **The secret never crosses in the clear.** `Owned` stores a Poseidon commitment to the caller's key bound to the request id; `refund_to_owner` opens it with a fresh witness. Completions have no witness row.
- **Nothing is hand-synced with the MPC.** Ledger path, kind byte, response field name and record version all come from the types.

One hazard the types cannot see: the MPC resolves a request as FAILED when the return data does not decode, so a non-conforming ERC-20 returning nothing produces an attested failure for a transfer that moved the tokens. Until the callee's return shape is declared per token, a contract on this API needs a callee allow-list.

[signet-sim](crates/signet-sim) is the MPC's reader and responder, so a flow round-trips under `cargo test` without an MPC. Costs are the same shape as compactc's and lower where the API does less: `supply` k14 / 11,474 rows against the port's k15 / 23,038; `complete_withdraw` k15 / 25,655 against the deployed k16 / 35,553 ([erc20_vault_pending.rs](crates/minocrab-contracts/tests/erc20_vault_pending.rs)).

### The outbox: a contention-free call queue

The pattern the blind ops exist for, and one Compact cannot write (every ledger read it compiles is a `popeq`; see "Blind ledger update" above). `Outbox<Filing, Env, WORDS>` is a `Pending` plus a primitive `Stream` whose accumulator is `(last nonce, last seen)` under `(Add, Max)`: a `call` files the transaction minus its nonce under the hash of the pre-record and lets the ledger add one to the nonce and snapshot both cells into the call's entry, blind; an `emit` — one request, anyone may prove it — reads that entry back (written once, so its `popeq` cannot go stale), builds the transaction at the snapshotted nonce, files the record and notifies the MPC; a settle is `Pending`'s, then the response's height must be after the call's last seen (the spec's C3) and last seen is raised by a blind max. No circuit reads either accumulator cell, so calls, emits and responses all land in one block; the audit is on the emitted Impact stream ([evm_outbox.rs](crates/minocrab-contracts/tests/evm_outbox.rs)).

```rust
#[derive(Ledger)]
struct Block { signet: Signet, calls: Outbox<Kinded<Transfer, 1>, HandleOwned<Amount>, 2> }

#[circuit]
fn call(c: &mut Circuit3, key_version: Uint<8>, token: Contract<Erc20>, to: Bytes<20>, amount: Uint<64>)
    -> Discloses<(Sent, Owner, Inserted)> {
    BLOCK.calls.call_owned::<Owner>(c, token, (to, amount.widen::<128>()), key_version, |_, _| Amount { .. });
    Discloses::of(())
}
#[circuit]
fn emit(c: &mut Circuit3, handle: Handle) -> Discloses<Emitted> { BLOCK.calls.emit(c, handle); Discloses::of(()) }
#[circuit]
fn complete(c: &mut Circuit3, ticket: Succeeded<Kinded<Transfer, 1>>) -> Discloses<(Settled, Height)> {
    let outcome = BLOCK.calls.complete(c, ticket);
    BLOCK.calls.raise_seen::<Height>(c, &outcome.env, outcome.output);   // C3, then the blind max
    Discloses::of(())
}
```

| circuit | k | rows | checked reads | of which shared |
|---|---|---|---|---|
| `call` | 10 | 924 | 1 (the handle's not-member check) | 0 |
| `emit` | 10 | 1,004 | 10 | 1 (the Signet request nonce, the protocol record's counter) |
| `complete` | 15 | 25,675 | 4 | 0 |
| `refund` | 15 | 26,073 | 4 | 0 |

The serial twin — a step that is not a monoid, such as a moving average — keeps the same `insert` / `take` / `combine` and adds a `sequence` that flushes one to four keys through one `popeq` of the accumulator ([fee_ema.rs](crates/minocrab-contracts/tests/fee_ema.rs): report k8 / 130 rows, sequence k10 / 1,008, settle k7 / 108).

## Porting kit

- `corpus/` is 673 pinned `.compact` sources and the 814 ZKIR circuits the pinned compactc produced ([corpus/README.org](corpus/README.org), [sources.json](corpus/sources.json))
- Rewrite a contract in the eDSL; the harness checks it against compactc's artifact, not your reading of the source
- The check is statement identity: same typed schema, same public-input stream on one shared `ProofPreimage`, both handed to Midnight's reference VM. Instruction streams may differ. Guard rejections and tampered inputs must agree too.

```rust
fn assert_call_compatible(ours: &IrSource, theirs: &IrSource, pi: &ProofPreimage) {
    assert_eq!(types(ours), types(theirs), "input schemas differ");
    assert_eq!(ours.outputs, theirs.outputs, "output schemas differ");

    let our_run = simulate(ours, pi).expect("our artifact accepts");
    let their_run = simulate(theirs, pi).expect("corpus artifact accepts");
    assert_eq!(our_run.pi_skips, their_run.pi_skips, "pi_skips differ");
    assert_eq!(our_run.pis, their_run.pis, "PI vectors differ");

    assert_eq!(ours.check(pi).expect("upstream accepts ours"), our_run.pi_skips);
    assert_eq!(theirs.check(pi).expect("upstream accepts theirs"), their_run.pi_skips);
}
```

Every ported circuit is wired this way ([erc20_vault_differential.rs](crates/minocrab-contracts/tests/erc20_vault_differential.rs), [differential_baseline.rs](crates/minocrab-ledger/tests/differential_baseline.rs), [adts_differential.rs](crates/minocrab-contracts/tests/adts_differential.rs), [bounded_differential.rs](crates/minocrab-contracts/tests/bounded_differential.rs)). New ports add a scenario builder and one call.

```
cargo test --workspace --release
```

## Performance

2026-09-05, Apple Silicon, pinned toolchain. Port `mc` vs compactc `cc` on the **identical statement**; prove = median of 3, RSS = peak of a fresh subprocess.

| circuit | k mc/cc | prove mc | prove cc | RAM mc | RAM cc |
|---|---|---|---|---|---|
| signBidirectional (singleton) | **11 / 16** | **0.14s** | 2.83s | **51MB** | 1,021MB |
| respond (singleton) | **10 / 16** | **0.09s** | 2.69s | **41MB** | 904MB |
| startDeposit | **11 / 14** | **0.15s** | 0.76s | **53MB** | 205MB |
| approveRouter | **11 / 14** | **0.14s** | 0.74s | **54MB** | 223MB |
| startSwap | **15 / 16** | **1.82s** | 3.35s | **674MB** | 1,189MB |
| startRedeem | **15 / 16** | **1.80s** | 3.22s | **615MB** | 1,168MB |
| completeSwap | 16 / 16 | 4.28s | 4.36s | 1.6GB | 1.6GB |
| initialise | 10 / 10 | 0.14s | 0.14s | 49MB | 49MB |

- The Signet singleton proves in **3–4% of compactc's time**, 5–6 `k` levels lower
- Every vault request circuit crosses at least one `k` boundary; the 2-word requests drop three
- Wins come from instruction selection around the protocol's hashes: one `div_mod` at a byte boundary and a native `reverse_bytes` per ABI word, where compactc spends ~640 rows a word on per-byte chains
- The nine settle circuits cut 12–16% of rows, but secp256k1 verify (~24,450 rows) floors both sides at k16; the port never costs more than compactc
- All 40 cells, methodology and the honest limits: [BENCHMARK.md](BENCHMARK.md)

## What Compact has and MinoCrab does not

Only real gaps; candidates that failed the check are in [notes/readme-research.org](notes/readme-research.org).

- Nested **coin arms**: `insertCoin` / `pushFrontCoin` reached *through* a nested path, e.g. `ms.lookup(k).insertCoin(coin, r)`. Nesting itself works to any depth over every shape Compact accepts, byte-equal to compactc on thirty circuits; only the coin arms at depth are missing, because no fixture circuit compiles one ([notes/coin-arms-nested-adts.org](notes/coin-arms-nested-adts.org)).
- A machine-checked skeleton of the *source language's* static plumbing. Compact's Agda spec checks its syntax representation and typing-rule skeletons and stops there (bound computation a `TODO`, subtyping a `postulate`). MinoCrab's machine-checked layer runs the other way: Lean models warrant the optimisation passes, the numeric bound asserts and the disclose gate. Both measured against each other: [VERIFICATION.md](VERIFICATION.md) §5, [notes/lean-port.org](notes/lean-port.org) §6.

## Layout

```
crates/minocrab-zkir       L0  ZKIR bindings: read/write/round-trip, reusing midnight-zkir
crates/minocrab-ir         L1  typed circuit builder over ZKIR instructions
crates/minocrab            L2  eDSL core: wires, visibility, disclosure tracking
crates/minocrab-ledger     L2.5 Impact ledger ops, bit-identical public-input encoding
crates/minocrab-std        L3  stdlib ports (hashing, ECDSA, Borsh serialization, Signet events)
crates/minocrab-macros          the thin decorators: #[circuit], the derives, #[interface]
crates/minocrab-sim        L5  native simulator: disclosure reports + per-region cost profiler
crates/minocrab-contracts       the sig-net corpus rewritten, plus the differential suites
crates/minocrab-bench           the head-to-head proving harness
crates/minocrab-abi             the interface/artifact agreement checker
crates/minocrab-interface-gen   compactc artifact → interface crate (CLI)
crates/signet-signer-interface  an interface crate: the Signet singleton
crates/xcall-target-interface   an interface crate, generated from a contract nobody ported
corpus/                         673 pinned Compact sources + 814 compactc artifacts
spec/                           the Borsh-subset specification, golden vectors, generated TS
```

Benchmark from a clean checkout (nix + direnv supply the pinned toolchain):

```
nix run .#bench
```

A contract depends on **`minocrab-std`** (which re-exports the eDSL and the decorators) plus `minocrab-sim` as a dev-dependency. Nine crates are meant for crates.io; nothing is published yet, because every `midnight-*` dependency is pinned to a git rev the registry does not carry ([PUBLISHING.md](PUBLISHING.md)). Consume it as a git dependency for now.

Deeper: `plan.org` (aim and design requirements), `milestones.org` (state of play), `notes/*.org` (findings and decisions of record).

## Using MinoCrab as a library

Like the [GHC API](https://hackage.haskell.org/package/ghc), MinoCrab exposes its innards so you build tooling *on* it without forking. Rust users get `minocrab_sim::v3::profile()` in a `#[test]`, criterion, the row snapshot as a regression gate. Non-Rust users get the `minocrab` CLI in `minocrab-sim`: `minocrab rows <file.zkir>...` and `minocrab diff <a> <b>` report `(k, rows)` over any ZKIR file, MinoCrab's or compactc's.

**Stability tiers** (each crate's docs open with its own tier statement):

| tier | what | where |
|---|---|---|
| **stable** | the v3 eDSL authoring core (`Circuit3` + its instruction methods, `Wire3`/`AnyWire3`, the typed leaves, the FAB alignment types, `Compiled3`/`IrSource`) | `minocrab`, `minocrab-std` |
| **stable** | the `Pass` trait + reference passes, the taint lint | `minocrab_ir::v3::{passes, taint}` |
| **stable** | the measurement API: `cost`, `profile`, `assert_max_k`, the calibrated `rowcost` tables, the `minocrab` CLI | `minocrab-sim` |
| **internal** | the raw `Builder3`/`Val` layers, the simulator VMs, behind the `unstable` cargo feature | `minocrab-ir`, `minocrab-sim` |
| **internal** | the Impact ledger-op layer, the interface generator | `minocrab-ledger`, `minocrab-interface-gen` |

The `unstable` gate is a hard wall for a pass or lint crate depending on `minocrab-ir` alone. The wider contract-authoring surface (ledger declarations, kernel, Borsh, disclosure vocabulary) is *not yet* under the stability promise; the line widens by decision, never by accident.

**Three ways to extend it, no fork:**

1. **A super-optimised gadget**: a crate on `minocrab-std` that builds a fragment (a keccak, a Merkle path, an ABI encoder) in fewer rows than the stdlib's. This is where the speed is: typed-layer instruction selection needs the type information ZKIR has erased. Prove it equivalent with the differential or spec harness.
2. **An optimisation pass**: implement `minocrab_ir::v3::passes::Pass`, a pure, total `Vec<Instruction> -> (Vec<Instruction>, Vec<String>)`, and compose with `passes::run_pipeline`. Passes see type-erased ZKIR, so they are the uniform-transform tail. `Pass::run` returns a `PassReport` whose `warnings` flag anything that could move the public-input stream; read it. Built-in passes carry machine-checked proofs (Kani-bounded, then Lean, `crates/minocrab-ir/lean/`), reflected as the `VerifiedPass` marker `run_pipeline_verified` requires; cite yours with `lean_proof!`.
3. **Measure**: `minocrab_sim::v3::{cost, profile}` give `(k, rows)` and a region-attributed breakdown; the calibrated primitive-cost tables (`minocrab-sim/examples/`) price individual gadgets.

Good passes or circuits: publish on cargo, or open a PR if they beat the stdlib. Lean proofs of equivalence are preferred and may be merged automatically.

The levers that cut gate counts are catalogued in [OPTIMIZATION.md](OPTIMIZATION.md); the library design of record is [notes/library-api.org](notes/library-api.org).
