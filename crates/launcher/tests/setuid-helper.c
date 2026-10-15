/* SPDX-License-Identifier: AGPL-3.0-or-later
 * The setuid escalation control for the launcher's hostile probe.
 * Build static, install root-owned and setuid under /usr, and pass its path as
 * LAUNCHER_TEST_SETUID_HELPER:
 *   cc -static -O2 -o aukora-probe-setuid setuid-helper.c
 *   install -o root -g root -m 4755 aukora-probe-setuid /usr/libexec/aukora-probe-setuid
 * Control (unconfined): `su -s /bin/sh nobody -c /usr/libexec/aukora-probe-setuid` exits 77.
 * Inside the sandbox the probe expects it NOT to exit 77 (no_new_privs, unmapped owner). */
#include <unistd.h>
int main(void) { return geteuid() != getuid() ? 77 : 0; }
