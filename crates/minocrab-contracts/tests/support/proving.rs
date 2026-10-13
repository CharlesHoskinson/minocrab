//! The in-process proving provider the real-proving gates share
//! (`signet_real_proof.rs`, M29 E; `signet_posting.rs`, M43 D).
//!
//! MECHANICAL TRANSLATION of `midnight_ledger::test_utilities`'
//! `CombinedProofProvider`, v3 arm only (`ledger/src/test_utilities.rs:749-818`).
//! The upstream one is a private struct behind the ledger's `test-utilities`
//! and `proving` features, and its resolver owns a `ZswapResolver` and a
//! `DustResolver`, which are network-fetched parameter sets these gates
//! never need.

use std::collections::BTreeMap;
use std::io;

use midnight_base_crypto::data_provider::MidnightDataProvider;
use midnight_base_crypto::rng::SplittableRng;
use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::proofs::{
    KeyLocation, Proof, ProofPreimage, ProvingKeyMaterial, ProvingProvider, Resolver, Zkir,
};
use minocrab_zkir::v3::IrSource;
use rand::{CryptoRng, Rng};

/// Key material keyed by `KeyLocation` — which
/// `support::signet_call::call_prototype` sets to the Compact circuit name,
/// the same name the managed directory's files carry and the same name the
/// deployed operations use as their entry point.
#[derive(Default, Clone)]
pub struct ManagedKeys(pub BTreeMap<String, ProvingKeyMaterial>);

impl Resolver for ManagedKeys {
    async fn resolve_key(&self, key: KeyLocation) -> io::Result<Option<ProvingKeyMaterial>> {
        Ok(self.0.get(key.0.as_ref()).cloned())
    }
}

pub struct V3ProvingProvider<'a, R: Rng + CryptoRng + SplittableRng> {
    pub rng: R,
    pub keys: &'a ManagedKeys,
    pub params: &'a MidnightDataProvider,
}

impl<R: Rng + CryptoRng + SplittableRng> ProvingProvider for V3ProvingProvider<'_, R> {
    async fn check(&self, preimage: &ProofPreimage) -> Result<Vec<Option<usize>>, anyhow::Error> {
        let material = self
            .keys
            .resolve_key(preimage.key_location.clone())
            .await?
            .ok_or_else(|| anyhow::anyhow!("no key material for '{}'", preimage.key_location.0))?;
        let ir = IrSource::load_ir_from_tagged(io::Cursor::new(&material.ir_source[..]))?;
        preimage.check(&ir)
    }

    async fn prove(
        self,
        preimage: &ProofPreimage,
        overwrite_binding_input: Option<Fr>,
    ) -> Result<Proof, anyhow::Error> {
        let mut preimage = preimage.clone();
        if let Some(binding_input) = overwrite_binding_input {
            preimage.binding_input = binding_input;
        }
        preimage
            .prove::<IrSource>(self.rng, self.params, self.keys)
            .await
            .map(|(proof, _)| proof)
    }

    fn split(&mut self) -> Self {
        V3ProvingProvider { rng: self.rng.split(), keys: self.keys, params: self.params }
    }

    fn resolver(&self) -> &impl Resolver {
        self.keys
    }
}

/// Peak RSS of this process, in bytes — `getrusage(RUSAGE_SELF)`, the same
/// measurement `crates/minocrab-bench` reports. Process-wide and MONOTONIC.
pub fn peak_rss_bytes() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    assert_eq!(rc, 0, "getrusage failed");
    let raw = ru.ru_maxrss as u64;
    // macOS reports bytes, Linux kilobytes.
    if cfg!(target_os = "macos") { raw } else { raw * 1024 }
}
