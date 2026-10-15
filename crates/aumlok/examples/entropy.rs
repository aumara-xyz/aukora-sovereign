fn main() {
    println!("minimum_bits={}", aumlok::phrase::MIN_ENTROPY_DISPLAY);
    println!("average_bits={}", aumlok::phrase::AVERAGE_ENTROPY_DISPLAY);
    println!("weakest_anchor={}", aumlok::phrase::WEAKEST_ANCHOR);
    println!(
        "exact_minimum=log2({})",
        aumlok::phrase::MIN_PROBABILITY_DENOMINATOR
    );
}
