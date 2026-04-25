fn main() {
    // Link to the RandomX library
    println!("cargo:rustc-link-lib=static=randomx");

    // Platform-specific configurations
    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-lib=msvcprt");
        println!("cargo:rustc-link-search=native=./lib");
    } else {
        println!("cargo:rustc-link-lib=dylib=stdc++");
        println!("cargo:rustc-link-search=native=/usr/local/lib");
    }
}
