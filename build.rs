fn main() {
    // Link to the RandomX library
    println!("cargo:rustc-link-lib=randomx");

    // Platform-specific configurations
    if cfg!(target_os = "windows") {
        // On Windows, use the Microsoft Visual C++ Runtime
        println!("cargo:rustc-link-lib=msvcprt");
        // Add lib directory in the project
        println!("cargo:rustc-link-search=native=./lib");
    } else {
        // On Unix-like systems (Linux, macOS), use stdc++
        println!("cargo:rustc-link-lib=stdc++");
        println!("cargo:rustc-link-search=native=/usr/local/lib");
    }
}
