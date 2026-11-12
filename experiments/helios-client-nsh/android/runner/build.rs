fn main() {
    println!("cargo:rustc-link-arg-cdylib=-Wl,-z,max-page-size=16384");
    println!("cargo:rustc-link-arg-cdylib=-Wl,-z,common-page-size=16384");
}
