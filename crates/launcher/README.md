# crates/launcher
- **Owns:** the cage (namespaces, Landlock, seccomp, cgroups, no network), cage profiles including the sub-cage that stays off, the boot record.
- **Never owns:** policy, or what runs inside.
- **May depend on:** canon.
- **Bricks:** 25, 26, 27, 28, 39 (NORTH-STAR.md).
