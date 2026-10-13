//! The erc20-vault verification harness: the reference model, the
//! executor and the differential suite's scenarios, on the flush-pattern
//! vault (M44).
//!
//! Compiled into every test binary that declares `mod vault`, each of which
//! uses only the part it needs — hence the blanket `dead_code` allowance.
#![allow(dead_code)]

pub mod artifact;
pub mod exec;
pub mod gen;
pub mod model;
pub mod ops;
pub mod prims;
pub mod tamper;
