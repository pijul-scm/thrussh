extern crate gcc;
fn main(){
    gcc::Config::new()
        .file("src/tweetnacl.c")
        .compile("libtweetnacl.a");
    println!("cargo:rustc-flags=-l static=tweetnacl")
}
