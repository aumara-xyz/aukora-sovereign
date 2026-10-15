use std::path::PathBuf;

pub fn prime_file(relative: &str) -> PathBuf {
    let root = std::env::var_os("AUKORA_PRIME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/Users/peterviviani/aukora-prime"));
    let file = root.join(relative);
    assert!(
        file.is_file(),
        "AUKORA_PRIME: required reference file {} is missing; set AUKORA_PRIME to the Prime checkout",
        file.display()
    );
    file
}
