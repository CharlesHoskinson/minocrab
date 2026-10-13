//! A frozen `(k, rows)` snapshot of every circuit in this crate.
//!
//! The const-generic refactor of M7 is a TYPE-level change: the sequence,
//! order and arguments of the `Circuit3` builder calls must not move, so
//! every circuit's cost must stay bit-identical. This test is the guard —
//! it prices each circuit with the same cost model the benchmark harness
//! uses (`minocrab_sim::v3::cost`, i.e. Midnight's own model) and compares
//! against the table below, generated at the commit that introduced it.
//!
//! The twelve benchmark circuits agree with the published numbers in
//! `BENCHMARK.md`.
//!
//! To regenerate after an INTENTIONAL cost change (a toolchain bump that
//! moves lowering is one — notes/version-bump.org):
//! `cargo test --release -p minocrab-contracts --test row_snapshot -- \
//!      --ignored regenerate_row_snapshot`, or `./bump.sh accept` to run
//! every regenerator at once. It rewrites the table below in place, so the
//! new baseline arrives as a reviewable diff.
//!
//! WHEN IT FIRES it says WHICH INSTRUCTIONS MOVED, not just that the rows
//! did. `(k, rows)` is a number, and a number is not a diagnosis; the
//! instruction-level answer is one dump comparison away, so this test runs it
//! itself. Every PASSING run refreshes a ZKIR baseline under the target
//! directory (`support::zkir_lines`, the `zkir_dump` rendering), and a
//! failing run diffs each moved circuit against it. Point
//! `MINOCRAB_ZKIR_BASELINE=<dir>` at a `zkir_dump` directory to diff against
//! a chosen commit instead.

mod support;

use support::{
    changed_lines, circuits, rewrite_generated_region, test_source, write_zkir_dump,
    zkir_baseline_dir, zkir_dump_name, zkir_lines, Circuit,
};

/// `(circuit, k, rows)` — frozen at "M7: freeze per-circuit (k, rows) in a
/// row-snapshot guard test".
const SNAPSHOT: &[(&str, u8, usize)] = &[
    // GENERATED BEGIN — rewritten by `regenerate_row_snapshot`
    ("erc20_vault::initialise", 10, 945),
    ("erc20_vault::set_gas_params", 10, 664),
    ("erc20_vault::add_allowed_token", 9, 374),
    ("erc20_vault::flush_queue", 13, 7078),
    ("erc20_vault::queue_attestation0", 15, 26017),
    ("erc20_vault::queue_attestation1", 15, 26065),
    ("erc20_vault::queue_attestation32", 15, 26151),
    ("erc20_vault::start_replace_nonce", 11, 1838),
    ("erc20_vault::send_replace_nonce", 11, 1165),
    ("erc20_vault::complete_replace_nonce", 10, 879),
    ("erc20_vault::start_approve_router", 11, 1064),
    ("erc20_vault::start_approve_stata", 10, 1014),
    ("erc20_vault::send_approve", 11, 1389),
    ("erc20_vault::complete_approve", 10, 908),
    ("erc20_vault::start_deposit", 11, 1240),
    ("erc20_vault::send_deposit", 11, 1570),
    ("erc20_vault::complete_deposit", 14, 11010),
    ("erc20_vault::start_withdraw", 15, 22237),
    ("erc20_vault::send_withdraw", 11, 1546),
    ("erc20_vault::complete_withdraw", 14, 10767),
    ("erc20_vault::start_swap", 15, 22388),
    ("erc20_vault::send_swap", 12, 2545),
    ("erc20_vault::complete_swap", 15, 30347),
    ("erc20_vault::start_supply", 15, 22112),
    ("erc20_vault::send_supply", 11, 1566),
    ("erc20_vault::complete_supply", 15, 20566),
    ("erc20_vault::start_redeem", 15, 22112),
    ("erc20_vault::send_redeem", 11, 1770),
    ("erc20_vault::complete_redeem", 15, 20566),
    ("erc20_vault_pending::initialize", 10, 814),
    ("erc20_vault_pending::deposit", 11, 1919),
    ("erc20_vault_pending::claim", 16, 35864),
    ("erc20_vault_pending::approve_router", 11, 1282),
    ("erc20_vault_pending::withdraw", 14, 11652),
    ("erc20_vault_pending::complete_withdraw", 15, 25745),
    ("erc20_vault_pending::refund_withdrawal", 16, 35714),
    ("erc20_vault_pending::swap", 14, 12587),
    ("erc20_vault_pending::complete_swap", 16, 45266),
    ("erc20_vault_pending::refund_swap", 16, 35854),
    ("erc20_vault_pending::approve_stata", 11, 1229),
    ("erc20_vault_pending::supply", 14, 11581),
    ("erc20_vault_pending::complete_supply", 16, 35785),
    ("erc20_vault_pending::refund_supply", 16, 35858),
    ("erc20_vault_pending::redeem", 14, 11758),
    ("erc20_vault_pending::complete_redeem", 16, 35785),
    ("erc20_vault_pending::refund_redeem", 16, 35858),
    ("signet_contract::sign_bidirectional", 11, 1205),
    ("signet_contract::respond", 10, 1004),
    ("signet_contract::respond_bidirectional", 11, 1330),
    ("attest::map_only", 8, 135),
    ("attest::verify_only", 15, 25276),
    ("attest::sha_verify", 16, 48988),
    ("attest::keccak_verify", 16, 51766),
    ("events::base", 8, 180),
    ("events::emit_n(1)", 9, 368),
    ("events::emit_n(2)", 10, 544),
    ("events::emit_n(4)", 10, 898),
    ("events_borsh::base", 8, 180),
    ("events_borsh::emit_n(1)", 9, 368),
    ("events_borsh::emit_n(2)", 10, 544),
    ("events_borsh::emit_n(4)", 10, 898),
    ("hashing::control(32)", 7, 118),
    ("hashing::control(64)", 8, 184),
    ("hashing::control(128)", 9, 336),
    ("hashing::control(256)", 10, 640),
    ("hashing::control(1024)", 12, 2486),
    ("hashing::persistent(32)", 13, 2013),
    ("hashing::persistent(64)", 13, 3943),
    ("hashing::persistent(128)", 13, 5975),
    ("hashing::persistent(256)", 14, 10040),
    ("hashing::persistent(1024)", 16, 34453),
    ("hashing::keccak(64)", 14, 4419),
    ("hashing::keccak(128)", 14, 4587),
    ("hashing::keccak(256)", 14, 9098),
    ("hashing::transient(32)", 8, 149),
    ("hashing::transient(256)", 10, 758),
    ("hashing::transient(1024)", 12, 2869),
    ("hashing::persistent_vec8", 14, 10147),
    ("xcall::local_base", 8, 180),
    ("xcall::call_once", 9, 297),
    ("xcall::call_emit", 9, 297),
    ("xcall::call_once_bound", 9, 297),
    ("xcall::call_twice", 9, 442),
    ("xcall::call_big", 10, 851),
    ("xcall::target_deposit", 8, 180),
    ("xcall::target_deposit_emit", 9, 368),
    ("xcall::target_deposit_big", 10, 640),
    ("xcall_with_payment::call_once", 9, 400),
    ("xcall_with_payment::request", 9, 255),
    ("xcall_with_payment::notify", 14, 11585),
    ("xcall_with_payment::pay", 14, 11687),
    ("xcall_with_payment::confirm_request", 8, 125),
    ("xcontract_events::deposit_via_vault", 9, 345),
    ("xcontract_events::token_deposit", 14, 10940),
    ("xcontract_events_borsh::token_deposit", 14, 10940),
    ("mint_tokens::mint_with_recipient_argument", 14, 9663),
    ("mint_tokens::mint_with_recipient_own_public_key", 14, 9807),
    ("serde_builtin::check_roundtrip", 15, 18408),
    ("test_caller::initialise", 9, 428),
    ("treasury::send", 11, 1754),
    ("treasury::complete", 15, 25703),
    ("treasury::refund", 15, 26120),
    ("bounded::b10", 6, 41),
    ("bounded::b300", 6, 41),
    ("bounded::b1000", 6, 41),
    ("bounded::b70000", 7, 41),
    ("bounded::b1", 6, 32),
    ("bounded::b2", 6, 33),
    ("bounded::b256", 6, 34),
    ("bounded::b255", 9, 41),
    ("bounded::b_enum", 6, 41),
    ("bounded::b_struct", 7, 120),
    ("bounded::b_compare", 7, 81),
    ("bounded_ledger::bl_write", 6, 36),
    ("bounded_ledger::bl_read", 6, 34),
    ("opaque::op_arg", 6, 32),
    ("opaque::op_ret", 6, 53),
    ("opaque::op_eq", 6, 57),
    ("opaque::op_default", 6, 35),
    ("opaque::op_cell", 6, 36),
    ("opaque::op_witness", 6, 36),
    ("opaque::op_map_value", 8, 130),
    ("opaque::op_map_key", 6, 41),
    ("opaque::op_set", 7, 75),
    ("opaque::op_maybe", 6, 38),
    ("opaque::op_bytes", 6, 36),
    ("opaque::op_struct", 7, 60),
    ("opaque::op_point", 9, 135),
    ("opaque::op_jubjub", 7, 63),
    ("adts::set_insert", 8, 125),
    ("adts::set_member", 8, 129),
    ("adts::set_remove", 8, 123),
    ("adts::set_size", 6, 35),
    ("adts::set_is_empty", 6, 41),
    ("adts::set_reset", 6, 32),
    ("adts::list_push_front", 8, 147),
    ("adts::list_pop_front", 6, 33),
    ("adts::list_head", 7, 94),
    ("adts::list_length", 6, 38),
    ("adts::list_is_empty", 6, 45),
    ("adts::list_reset", 6, 38),
    ("adts::map_insert_default", 8, 128),
    ("adts::map_reset", 6, 32),
    ("adts::mt_insert", 13, 2026),
    ("adts::mt_insert_index", 13, 2059),
    ("adts::mt_insert_hash", 8, 139),
    ("adts::mt_insert_hash_index", 8, 172),
    ("adts::mt_insert_index_default", 13, 1971),
    ("adts::mt_check_root", 7, 67),
    ("adts::mt_is_full", 6, 45),
    ("adts::mt_reset", 6, 37),
    ("adts::hmt_insert", 13, 2040),
    ("adts::hmt_insert_index", 13, 2072),
    ("adts::hmt_insert_hash", 8, 153),
    ("adts::hmt_insert_hash_index", 8, 185),
    ("adts::hmt_insert_index_default", 13, 1984),
    ("adts::hmt_check_root", 7, 66),
    ("adts::hmt_is_full", 6, 45),
    ("adts::hmt_reset_history", 6, 44),
    ("adts::hmt_reset", 6, 51),
    ("kernel_tokens::k_mint_unshielded", 8, 159),
    ("kernel_tokens::k_claim_unshielded_coin_spend", 9, 387),
    ("kernel_tokens::k_inc_unshielded_outputs", 8, 180),
    ("kernel_tokens::k_inc_unshielded_inputs", 8, 180),
    ("kernel_tokens::k_balance", 8, 155),
    ("kernel_tokens::k_balance_less_than", 8, 215),
    ("kernel_tokens::k_balance_greater_than", 8, 215),
    ("kernel_tokens::k_block_time_less_than", 7, 78),
    ("kernel_tokens::k_block_time_greater_than", 7, 78),
    ("kernel_tokens::s_block_time_lt", 7, 78),
    ("kernel_tokens::s_block_time_gte", 7, 80),
    ("kernel_tokens::s_block_time_gt", 7, 78),
    ("kernel_tokens::s_block_time_lte", 7, 80),
    ("kernel_tokens::s_unshielded_balance", 8, 155),
    ("kernel_tokens::s_unshielded_balance_lt", 8, 215),
    ("kernel_tokens::s_unshielded_balance_gte", 8, 217),
    ("kernel_tokens::s_unshielded_balance_gt", 8, 215),
    ("kernel_tokens::s_unshielded_balance_lte", 8, 217),
    ("kernel_tokens::s_receive_unshielded", 8, 180),
    ("kernel_tokens::s_send_unshielded", 9, 476),
    ("kernel_tokens::s_mint_unshielded_token", 13, 4256),
    ("kernel_tokens::s_merge_coin", 15, 17751),
    ("kernel_tokens::s_merge_coin_immediate", 15, 17733),
    ("kernel_tokens::s_send_shielded", 15, 23615),
    ("coins::set_insert_coin", 13, 6106),
    ("coins::map_insert_coin", 13, 6198),
    ("coins::list_push_front_coin", 13, 6136),
    ("nested::map_insert", 8, 238),
    ("nested::map_insert_default", 8, 220),
    ("nested::map_lookup", 8, 219),
    ("nested::map_member", 8, 221),
    ("nested::map_remove", 8, 215),
    ("nested::map_size", 8, 127),
    ("nested::map_is_empty", 8, 133),
    ("nested::map_reset", 8, 125),
    ("nested::outer_insert_default", 8, 125),
    ("nested::list_push_front", 8, 239),
    ("nested::list_pop_front", 8, 124),
    ("nested::list_length", 8, 130),
    ("nested::list_head", 8, 186),
    ("nested::list_is_empty", 8, 137),
    ("nested::list_reset", 8, 131),
    ("nested::set_insert", 8, 217),
    ("nested::set_remove", 8, 215),
    ("nested::set_member", 8, 221),
    ("nested::set_reset", 8, 125),
    ("nested::counter_increment", 8, 122),
    ("nested::counter_read", 8, 126),
    ("nested::counter_reset", 8, 128),
    ("nested::mt_insert", 13, 2118),
    ("nested::mt_check_root", 8, 159),
    ("nested::mt_reset", 8, 130),
    ("nested::hmt_insert", 13, 2132),
    ("nested::hmt_reset_history", 8, 135),
    ("nested::hmt_reset", 8, 144),
    ("nested::deep_insert", 9, 330),
    ("nested::deep_lookup", 9, 311),
    ("manager::is_registered", 8, 129),
    ("manager::account_record", 9, 311),
    ("manager::shielded_account_balance", 13, 4000),
    ("manager::unshielded_account_balance", 13, 4000),
    ("manager::pool_value", 8, 158),
    ("manager::pool_has_colour", 8, 129),
    ("manager::deposit_shielded", 16, 38488),
    ("manager::deposit_unshielded", 13, 4150),
    ("manager::execute", 18, 209316),
    // GENERATED END
];

#[test]
fn every_circuit_matches_its_frozen_cost() {
    let circuits = circuits();
    assert_eq!(
        circuits.len(),
        SNAPSHOT.len(),
        "snapshot table covers {} circuits but {} are built — add the new \
         circuit to SNAPSHOT (regenerate with the `regenerate_row_snapshot` test)",
        SNAPSHOT.len(),
        circuits.len()
    );

    let mut failures = Vec::new();
    let mut moved: Vec<Circuit> = Vec::new();
    for ((name, build), &(snap_name, k, rows)) in circuits.iter().zip(SNAPSHOT) {
        assert_eq!(*name, snap_name, "snapshot table out of order");
        let (got_k, got_rows) = minocrab_sim::v3::cost(&build().ir);
        if (got_k, got_rows) != (k, rows) {
            failures.push(format!(
                "  {name}: expected k={k} rows={rows}, got k={got_k} rows={got_rows} \
                 ({:+})",
                got_rows as i64 - rows as i64
            ));
            moved.push((name, *build));
        }
    }

    let baseline = zkir_baseline_dir();
    if failures.is_empty() {
        // The baseline is only ever written from a state the frozen table
        // agrees with, so a diff against it is a diff against a green tree.
        write_zkir_dump(&baseline);
        return;
    }
    panic!(
        "circuit cost changed — this refactor must be type-level only:\n{}\n\n{}",
        failures.join("\n"),
        instruction_diffs(&moved, &baseline)
    );
}

/// The instruction-level answer for every circuit whose cost moved: the ZKIR
/// this build produces against the baseline dump, `-` baseline, `+` now.
///
/// Per circuit at most [`MAX_DIFF_LINES`] changed lines, because a k16
/// circuit's stream is tens of thousands and the movement is what is wanted.
fn instruction_diffs(moved: &[Circuit], baseline: &std::path::Path) -> String {
    let mut out = String::new();
    let mut missing = Vec::new();
    for (name, build) in moved {
        let path = baseline.join(zkir_dump_name(name));
        let Ok(before) = std::fs::read_to_string(&path) else {
            missing.push(*name);
            continue;
        };
        let before: Vec<&str> = before.lines().collect();
        let after = zkir_lines(&build().ir);
        let after: Vec<&str> = after.iter().map(String::as_str).collect();
        out.push_str(&format!("  {name} — `-` baseline, `+` this build:\n"));
        out.push_str(&changed_lines(&before, &after, MAX_DIFF_LINES));
    }
    if out.is_empty() {
        out.push_str("No ZKIR baseline to diff against");
    } else if !missing.is_empty() {
        out.push_str(&format!("\nNo baseline for: {}", missing.join(", ")));
    }
    out.push_str(&format!(
        "\n(baseline: {}. It is written by every PASSING run of this test, so \
         a first-run failure has none. For a diff against a chosen commit: \
         `MINOCRAB_ZKIR_DUMP=/tmp/before cargo test -p minocrab-contracts \
         --test zkir_dump -- --ignored dump_every_circuits_zkir` at that \
         commit, then re-run this test with \
         `MINOCRAB_ZKIR_BASELINE=/tmp/before`.)\n",
        baseline.display()
    ));
    out
}

/// Changed lines printed per moved circuit before the rest are counted.
const MAX_DIFF_LINES: usize = 60;

/// The failure renderer is the whole value of this instrument when it fires,
/// so the part `interface_snapshot`'s diff test does not cover — dropping the
/// unchanged lines and capping the rest — gets its own check.
#[test]
fn the_instruction_diff_keeps_only_the_movement_and_caps_it() {
    let before = ["a", "b", "c", "d"];
    let after = ["a", "x", "c", "d"];
    assert_eq!(changed_lines(&before, &after, 60), "    - b\n    + x\n");
    assert_eq!(
        changed_lines(&before, &after, 1),
        "    - b\n    … 1 more changed lines\n"
    );
    assert_eq!(changed_lines(&before, &before, 60), "");

    // Past the LCS limit it falls back to a positional comparison, which
    // still reports the movement — this is the path that must not allocate
    // a table.
    let long_before: Vec<String> = (0..6000).map(|i| i.to_string()).collect();
    let mut long_after = long_before.clone();
    long_after[4711] = "moved".to_string();
    let long_before: Vec<&str> = long_before.iter().map(String::as_str).collect();
    let long_after: Vec<&str> = long_after.iter().map(String::as_str).collect();
    assert_eq!(
        changed_lines(&long_before, &long_after, 60),
        "    - 4711\n    + moved\n"
    );
}

/// Regeneration helper: rewrites the SNAPSHOT table in this file.
#[test]
#[ignore = "regeneration helper, not a check"]
fn regenerate_row_snapshot() {
    let mut body = String::new();
    for (name, build) in circuits() {
        let (k, rows) = minocrab_sim::v3::cost(&build().ir);
        body.push_str(&format!("    (\"{name}\", {k}, {rows}),\n"));
    }
    rewrite_generated_region(&test_source("row_snapshot.rs"), &body);
}
