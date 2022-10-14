use std::{env, fs};
use std::fs::File;
use std::path::Path;

fn main() {
    built::write_built_file().expect("Failed to acquire build-time information");
    // newer version of the spec for reasons
    let src = "spec-serial.json";
    println!("cargo:rerun-if-changed={}", src);
    let file = File::open(src).unwrap();
    let spec = serde_json::from_reader(file).unwrap();
    let mut generator = progenitor::Generator::default();

    let content = generator.generate_text(&spec).unwrap();

    let mut out_file = Path::new(&env::var("OUT_DIR").unwrap()).to_path_buf();
    out_file.push("codegen.rs");

    fs::write(out_file, content).unwrap();
}
