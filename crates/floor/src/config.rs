// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{evidence::OwnerBinding, protected::ProtectedStore, Refusal, Result};
use serde::Deserialize;
use std::path::PathBuf;

const CONFIG_MAX_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
struct NodeConfig {
    node_id: String,
    owner_hostname: String,
    owner_origin: String,
    webauthn: WebAuthn,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WebAuthn {
    rp_id: String,
    origin: String,
}

pub fn read_owner_binding(path: impl Into<PathBuf>) -> Result<OwnerBinding> {
    read_binding(&ProtectedStore::new(path))
}

fn read_binding(store: &ProtectedStore) -> Result<OwnerBinding> {
    let bytes = store
        .read(CONFIG_MAX_BYTES)?
        .ok_or(Refusal("floor:config-absent"))?;
    canon::parse(&bytes).map_err(|_| Refusal("floor:config-malformed"))?;
    let config: NodeConfig =
        serde_json::from_slice(&bytes).map_err(|_| Refusal("floor:config-malformed"))?;
    if !crate::is_hex(&config.node_id, 32)
        || config.owner_hostname.is_empty()
        || config.webauthn.rp_id != config.owner_hostname
        || config.owner_origin != format!("https://{}", config.owner_hostname)
        || config.webauthn.origin != config.owner_origin
    {
        return Err(Refusal("floor:config-malformed"));
    }
    Ok(OwnerBinding {
        node_id: config.node_id,
        rp_id: config.webauthn.rp_id,
        origin: config.webauthn.origin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    fn fixture() -> (tempfile::TempDir, ProtectedStore) {
        let dir = tempfile::Builder::new()
            .prefix(".floor-config-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let store = ProtectedStore::test(dir.path().join("node.json"), uid, dir.path().into());
        fs::write(store.path_for_test(), serde_json::to_vec(&serde_json::json!({
            "node_id":"11".repeat(16),
            "owner_hostname":"owner-s2-1-2-3-4.sslip.io",
            "owner_origin":"https://owner-s2-1-2-3-4.sslip.io",
            "webauthn":{"rp_id":"owner-s2-1-2-3-4.sslip.io", "origin":"https://owner-s2-1-2-3-4.sslip.io"},
            "release_floor":false
        })).unwrap()).unwrap();
        // A root install writes 0644; the folder and file must not inherit a group-writable umask (Ubuntu's is 002).
        fs::set_permissions(store.path_for_test(), fs::Permissions::from_mode(0o644)).unwrap();
        (dir, store)
    }

    #[test]
    fn antibody_floor_configured_real_hostname_is_read_from_protected_config() {
        let (_dir, store) = fixture();
        assert_eq!(
            read_binding(&store).unwrap(),
            OwnerBinding {
                node_id: "11".repeat(16),
                rp_id: "owner-s2-1-2-3-4.sslip.io".into(),
                origin: "https://owner-s2-1-2-3-4.sslip.io".into(),
            }
        );
    }

    #[test]
    fn antibody_floor_config_refuses_service_writable_files() {
        let (_dir, store) = fixture();
        for mode in [0o664, 0o646, 0o666] {
            fs::set_permissions(store.path_for_test(), fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(read_binding(&store), Err(Refusal("floor:protection")));
        }
    }

    #[test]
    fn antibody_floor_config_refuses_nonroot_owner() {
        let (_dir, store) = fixture();
        let wrong_owner = ProtectedStore::test(
            store.path_for_test(),
            fs::metadata(store.path_for_test()).unwrap().uid() + 1,
            store.path_for_test().parent().unwrap().into(),
        );
        assert_eq!(read_binding(&wrong_owner), Err(Refusal("floor:protection")));
    }

    #[test]
    fn antibody_floor_config_refuses_symbolic_and_hard_links() {
        let (dir, store) = fixture();
        let saved = dir.path().join("saved.json");
        fs::rename(store.path_for_test(), &saved).unwrap();
        symlink(&saved, store.path_for_test()).unwrap();
        assert_eq!(read_binding(&store), Err(Refusal("floor:symlink")));
        fs::remove_file(store.path_for_test()).unwrap();
        fs::hard_link(saved, store.path_for_test()).unwrap();
        assert_eq!(read_binding(&store), Err(Refusal("floor:hardlink")));
    }

    #[test]
    fn antibody_floor_config_size_is_bounded_before_parsing() {
        let (_dir, store) = fixture();
        fs::write(store.path_for_test(), vec![b' '; CONFIG_MAX_BYTES + 1]).unwrap();
        assert_eq!(read_binding(&store), Err(Refusal("floor:size")));
    }

    #[test]
    fn antibody_floor_config_rejects_values_outside_canonical_json() {
        let (_dir, store) = fixture();
        let bytes = fs::read(store.path_for_test()).unwrap();
        let mut bad = String::from_utf8(bytes).unwrap();
        bad.insert_str(1, "\"unrecognized\":1.5,");
        fs::write(store.path_for_test(), bad).unwrap();
        assert_eq!(read_binding(&store), Err(Refusal("floor:config-malformed")));
    }

    #[test]
    fn config_schema_and_owner_origin_must_agree() {
        let (_dir, store) = fixture();
        let genuine: serde_json::Value =
            serde_json::from_slice(&fs::read(store.path_for_test()).unwrap()).unwrap();
        for field in [
            "node_id",
            "owner_hostname",
            "owner_origin",
            "rp_id",
            "origin",
        ] {
            let mut bad = genuine.clone();
            if field == "rp_id" || field == "origin" {
                bad["webauthn"][field] = serde_json::json!("mismatch");
            } else {
                bad[field] = serde_json::json!("mismatch");
            }
            fs::write(store.path_for_test(), serde_json::to_vec(&bad).unwrap()).unwrap();
            assert_eq!(read_binding(&store), Err(Refusal("floor:config-malformed")));
        }
        fs::write(
            store.path_for_test(),
            b"{\"node_id\":\"a\",\"node_id\":\"b\"}",
        )
        .unwrap();
        assert_eq!(read_binding(&store), Err(Refusal("floor:config-malformed")));
        fs::remove_file(store.path_for_test()).unwrap();
        assert_eq!(read_binding(&store), Err(Refusal("floor:config-absent")));
    }
}
