use std::fs;

fn main() {
    let path = "hca.toml";
    if fs::metadata(path).is_err() {
        panic!("Missing required config file: {}", path);
    }
    println!("cargo:rerun-if-changed={}", path);
}
