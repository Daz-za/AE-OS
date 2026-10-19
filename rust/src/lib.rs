//! Verifier for AE-OS Receipts v0 (`spec/receipts-v0.md`).
//!
//! This crate checks receipts, consistency proofs and whole log directories written by
//! any AE-OS Receipts implementation. It shares its test vectors with the Python
//! reference implementation (`testvectors/receipts-v0.json`), and reports the same
//! problems in the same words, so an auditor gets the same answer from either.
//!
//! It verifies only: creating logs and signing checkpoints stays with the log operator.

pub mod canon;
pub mod merkle;
pub mod verify;

pub use verify::{
    verify_consistency_doc, verify_log, verify_receipt, Checkpoint, LogFiles, VerifyReport,
};
