use std::env;

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let stack_argument = match env::var("CARGO_CFG_TARGET_ENV").as_deref() {
        Ok("msvc") => "/STACK:33554432",
        Ok("gnu") => "-Wl,--stack,33554432",
        _ => return,
    };

    println!("cargo:rustc-link-arg-bin=preflightx={stack_argument}");
}
