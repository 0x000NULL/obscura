fn main() {
    println!("cargo:rustc-link-lib=randomx");
    println!("cargo:rustc-link-search=native=/usr/local/lib");
} 