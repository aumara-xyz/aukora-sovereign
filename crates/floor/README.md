# crates/floor
- **Owns:** the release floor and high-water marks; a spent approval never revives; the clone guard, later; the plugin fingerprint gate's data and decisions (`plugins`): the owner-approved set of engine plugin digests, its pinned hash, and which found packages may be loaded.
- **Never owns:** approvals.
- **May depend on:** canon, aura.
- **Bricks:** 65, 110, 111 (NORTH-STAR.md).
