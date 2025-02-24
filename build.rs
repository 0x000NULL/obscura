use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let lib_dir = manifest_dir.join("lib");

    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    // Link against RandomX library
    println!("cargo:rustc-link-lib=static=randomx");
    
    // Link against MSVC runtime libraries for release build
    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:MSVCRTD");
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:LIBCMTD");
        println!("cargo:rustc-link-arg=/DEFAULTLIB:MSVCRT");
    }

    // Rebuild if the build script changes
    println!("cargo:rerun-if-changed=build.rs");
} 