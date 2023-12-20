fn main() {
    if !cfg!(test) {
        // Generate C++ header for raw types
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        cbindgen::Builder::new()
            .with_crate(crate_dir)
            .with_language(cbindgen::Language::Cxx)
            .with_no_includes()
            .with_namespaces(&["hsm"])
            .with_include_guard("RAW_JOBS_H")
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file("target/RawJobs.h");
    }
}
