// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn antibody_missing_approval_targets_are_unknown_proposals() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let id = "48".repeat(16);
    runtime.block_on(async {
        let assertion = crate::owner::tests::assertion("unused", 1);
        for (operation, body) in [
            (Operation::ApprovalChallenge, json!({"id":id})),
            (Operation::ApprovalDespiteChallenge, json!({"id":id})),
            (
                Operation::ApprovalDecide,
                json!({"id":id,"approve":true,"assertion":assertion}),
            ),
            (
                Operation::ApprovalDespiteDecide,
                json!({"id":id,"assertion":assertion}),
            ),
        ] {
            let error = node
                .test_call("owner-lookup", operation, body)
                .await
                .unwrap_err();
            assert_eq!(error.code, "gate:unknown-proposal", "{operation:?}");
            assert_eq!(error.status, StatusCode::NOT_FOUND, "{operation:?}");
        }
    });
}

#[test]
fn antibody_boot_probe_refusal_guidance_preserves_containment() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let mut config = node.config.clone();
    config.boot_probe = true;
    drop(node);
    let node = Node::open(config, runtime.handle().clone()).unwrap();
    node.runtime.lock().unwrap().agent = crate::boot_probe::FAILURE.into();
    let approvals = node.owner_call(Operation::Approvals, json!({})).unwrap();
    let card = approvals["pending"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "boot-probe-refusal")
        .unwrap();
    let next = card["card"]["facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|fact| fact[0] == "next")
        .unwrap();
    assert_eq!(
        next[1],
        "Inspect the boot.facts probe result, repair the reported containment failure, then retry the start"
    );
}

#[test]
fn antibody_immune_documentation_states_automatic_replay_budget() {
    let readme = include_str!("../../../immune/README.md");
    assert!(readme.contains("Each automatic replay retains its 120-second budget"));
    assert!(!readme.contains("sixty-second budget"));
}
