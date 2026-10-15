// SPDX-License-Identifier: AGPL-3.0-or-later

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let corpus = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("corpus");
    // A file has no children: this missing watch forces enumeration of the current checkout.
    println!("cargo:rerun-if-changed=build.rs/.checkout");
    println!("cargo:rerun-if-changed=corpus");
    let mut files: Vec<_> = fs::read_dir(&corpus)
        .expect("antibody corpus directory")
        .map(|entry| entry.expect("antibody corpus entry").path())
        .filter(|path| path.extension().is_some_and(|suffix| suffix == "json"))
        .collect();
    files.sort();
    let mut source = String::from("const EMBEDDED: &[&[u8]] = &[\n");
    for path in files {
        let relative = path.strip_prefix(&corpus).unwrap().to_str().unwrap();
        println!("cargo:rerun-if-changed=corpus/{relative}");
        source.push_str(&format!(
            "include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), {:?})),\n",
            format!("/corpus/{relative}")
        ));
    }
    source.push_str("];\n");
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("corpus.rs");
    if !fs::read(&output).is_ok_and(|existing| existing == source.as_bytes()) {
        fs::write(output, source).expect("write embedded corpus list");
    }
}
