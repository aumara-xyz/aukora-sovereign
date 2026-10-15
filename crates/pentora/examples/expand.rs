// SPDX-License-Identifier: AGPL-3.0-or-later

use pentora::expand;

fn main() {
    for root_hex in std::env::args().skip(1) {
        let root = hex::decode(&root_hex).expect("root hex");
        let expansion = expand(&root).expect("32-byte root");
        println!(
            "{} {}",
            hex::encode(expansion.digest),
            hex::encode(expansion.trits)
        );
    }
}
