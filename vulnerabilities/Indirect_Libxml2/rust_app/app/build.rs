use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=COMP_A_LIB_DIR");
    println!("cargo:rerun-if-env-changed=COMP_B_LIB_DIR");
    println!("cargo:rerun-if-env-changed=LIBXML2_LIB_DIR");

    if let Ok(dir) = env::var("COMP_A_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", dir);
        println!("cargo:rustc-link-lib=compa");
    }
    if let Ok(dir) = env::var("COMP_B_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", dir);
        println!("cargo:rustc-link-lib=compb");
    }
    if let Ok(dir) = env::var("LIBXML2_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", dir);
        println!("cargo:rustc-link-lib=xml2");
    }
}
