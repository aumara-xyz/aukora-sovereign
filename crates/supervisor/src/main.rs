// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

fn main() {
    eprintln!("{}", canon::codes::SUPERVISOR_NOT_READY);
    std::process::exit(2);
}
