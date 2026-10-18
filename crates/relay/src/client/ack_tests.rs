// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deterministic relay OK frames; no sockets or external relay.
use super::*;

#[test]
fn stored_duplicates_are_accepted_and_rate_limits_remain_retryable() {
    let id = "ab".repeat(32);
    for (accepted, message, expected) in [
        (
            false,
            "duplicate: already stored",
            SubmissionStatus::Accepted,
        ),
        (false, "rate-limited: try later", SubmissionStatus::Unknown),
        (false, "blocked: denied", SubmissionStatus::Rejected),
        (false, "duplicate-looking prose", SubmissionStatus::Rejected),
        (true, "", SubmissionStatus::Accepted),
    ] {
        let frame = Frame::parse(&json!(["OK", id, accepted, message]).to_string()).unwrap();
        let (actual_id, accepted, reason) = frame.ack().unwrap();
        assert_eq!(actual_id, id);
        assert_eq!(submission_status(accepted, reason), expected);
    }
}
