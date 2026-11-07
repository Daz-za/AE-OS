//! Verifier for AE-OS action records (`spec/action-records-v1.md`).
//!
//! This crate checks action records with their Receipts, consistency proofs and whole audit
//! trail directories written by any AE-OS implementation, including version 0 `aeos-receipt/v0`
//! documents. It shares its test vectors with the Python reference implementation
//! (`testvectors/action-records-v1.json` and the frozen `testvectors/receipts-v0.json`), and reports the same
//! problems in the same words, so an auditor gets the same answer from either.
//!
//! It verifies only: creating logs and signing checkpoints stays with the log operator.

pub mod canon;
pub mod merkle;
pub mod verify;

#[allow(deprecated)]
pub use verify::verify_receipt;
pub use verify::{
    before_pending, verify_action_record, verify_action_record_detail, verify_consistency_doc,
    verify_log, Checkpoint, LogFiles, SignatureState, VerifyReport,
};
