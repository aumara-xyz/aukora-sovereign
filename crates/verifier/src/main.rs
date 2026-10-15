// SPDX-License-Identifier: AGPL-3.0-or-later
//! The command exists in wave 0 but never claims to have verified an export.
#![forbid(unsafe_code)]

use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    if args.next().is_none() {
        eprintln!("{}", verifier::USAGE);
        return ExitCode::from(64);
    }
    eprintln!("{}", verifier::UNIMPLEMENTED);
    ExitCode::from(1)
}
