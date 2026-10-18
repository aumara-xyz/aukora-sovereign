// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

struct Fixture { dir: PathBuf }
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.dir); }
}
fn fixture() -> Fixture {
    let tag = hex(random32().unwrap().as_ref());
    let dir = std::env::temp_dir().join(format!("kira-rate-{}", &tag[..16]));
    private_dir(&dir).unwrap();
    Fixture { dir }
}

#[test]
fn a_corrupt_or_invalid_file_fills_every_window_and_stays_full_after_restart() {
    let f = fixture();
    for bytes in [b"broken".as_slice(), b"{}", br#"{"version":2,"blocked_at":null,"writes":{}}"#,
        br#"{"version":1,"writes":{}}"#] {
        write_private(&f.dir.join(FILE), bytes, false).unwrap();
        let mut budget = Budget::open(&f.dir, 100).unwrap();
        assert_eq!(budget.reserve(&f.dir, "claude", 100), Err(refuse("rate-limited")));
        let mut restarted = Budget::open(&f.dir, 101).unwrap();
        assert_eq!(restarted.reserve(&f.dir, "new-agent", 159), Err(refuse("rate-limited")));
        restarted.reserve(&f.dir, "new-agent", 160).unwrap();
        assert_eq!(Budget::open(&f.dir, 160).unwrap().writes["new-agent"], [160]);
    }
}

#[test]
fn sliding_windows_expire_without_resetting_other_agents_and_ignore_uncommitted_temp() {
    let f = fixture();
    let mut budget = Budget::open(&f.dir, 100).unwrap();
    for _ in 0..RATE_WRITES {
        budget.reserve(&f.dir, "claude", 100).unwrap();
        budget.reserve(&f.dir, "grok", 110).unwrap();
    }
    // A crash before rename leaves the last committed window, never a partially written replacement.
    fs::write(f.dir.join("write-rate.json.new"), b"interrupted").unwrap();
    let mut restarted = Budget::open(&f.dir, 159).unwrap();
    assert_eq!(restarted.reserve(&f.dir, "claude", 159), Err(refuse("rate-limited")));
    restarted.reserve(&f.dir, "claude", 160).unwrap();
    assert_eq!(restarted.reserve(&f.dir, "grok", 160), Err(refuse("rate-limited")));
    restarted.reserve(&f.dir, "grok", 170).unwrap();
    // Clock rollback cannot expire a future timestamp early.
    assert_eq!(Budget::open(&f.dir, 90).unwrap().writes["grok"], [170]);
}
