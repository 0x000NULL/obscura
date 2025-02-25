fn main() {
    // Tell cargo to look for static libraries in the specified directory
    println!("cargo:rustc-link-search=native=lib");

    // Link against RandomX library
    println!("cargo:rustc-link-lib=static=randomx");

    // For Windows MSVC, we need these
    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-lib=dylib=msvcrt");
        println!("cargo:rustc-link-lib=dylib=user32");
        println!("cargo:rustc-link-lib=dylib=advapi32");
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:LIBCMT");
    }

    // Rebuild if the build script changes
    println!("cargo:rerun-if-changed=build.rs");
}
