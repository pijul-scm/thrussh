extern crate gcc;
extern crate regex;
use std::fs::File;
use std::env;
use std::path::Path;
use std::io::prelude::*;
use std::io::BufReader;
use regex::*;
use std::collections::HashMap;


fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("tweetnacl.rs");
    let mut f = File::create(&dest_path).unwrap();
    writeln!(f,"use libc::{{c_int, c_ulonglong}};").unwrap();

    let ifdef = Regex::new(r"#ifndef .*").unwrap();
    let define_str = Regex::new(r#"^#define crypto_(\S*)\s+"(\S+)"$"#).unwrap();
    let define_num = Regex::new(r#"^#define crypto_(\S*)\s+(\d+)$"#).unwrap();
    let define_define = Regex::new(r#"^#define crypto_(\S*)\s+(\S+)$"#).unwrap();
    let ext = Regex::new(r"^extern\s+(\S*)\s+crypto_(.*)\((.*)\);$").unwrap();

    let mut defines = HashMap::new();
    let mut in_extern_block = false;
    {
        let tweetnacl_h = BufReader::new(
            File::open(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("tweetnacl.h")).unwrap()
        );
        for i in tweetnacl_h.lines() {
            let i = i.unwrap();
            if ifdef.is_match(&i) {

                // writeln!(f, "ifdef {:?}", i).unwrap();

            } else if let Some(captures) = define_str.captures(&i) {

                if in_extern_block {
                    writeln!(f,"}}").unwrap();
                    in_extern_block = false;
                }
                if !check_name(captures.at(1).unwrap()) {
                    writeln!(f,"#[allow(non_upper_case_globals)]").unwrap();
                }
                writeln!(f,"pub const {}:&'static str = {:?};",
                         captures.at(1).unwrap(),
                         captures.at(2).unwrap()).unwrap();

                defines.insert(i.clone(), "&'static str");
                
            } else if let Some(captures) = define_num.captures(&i) {

                if in_extern_block {
                    writeln!(f,"}}").unwrap();
                    in_extern_block = false;
                }
                writeln!(f,"pub const {}:usize = {};",
                         captures.at(1).unwrap(),
                         captures.at(2).unwrap()).unwrap();
                
                defines.insert(i.clone(), "usize");

            } else if let Some(captures) = define_define.captures(&i) {

                let j = if let Some(j) = defines.get(&i) {
                    if in_extern_block {
                        writeln!(f,"}}").unwrap();
                        in_extern_block = false;
                    }

                    if j == &"usize" {
                        writeln!(f,"pub const {}:{} = {};",
                                 captures.at(1).unwrap(),
                                 j,
                                 captures.at(2).unwrap()).unwrap();
                    } else {
                        writeln!(f,"pub const {}:{} = {:?};",
                                 captures.at(1).unwrap(),
                                 j,
                                 captures.at(2).unwrap()).unwrap();
                    }
                    Some(j.clone())
                } else { None };

                if let Some(j) = j {
                    defines.insert(i.clone(), j);
                }

            } else if let Some(captures) = ext.captures(&i) {

                if !in_extern_block {
                    writeln!(f,"extern \"C\" {{").unwrap();
                    in_extern_block = true;
                }


                write!(f,"pub fn {}(", captures.at(2).unwrap()).unwrap();
                let mut k = 0;
                let args = ["a","b","c","d","e","f"];
                for argu in captures.at(3).unwrap().split(',') {

                    if k > 0 {
                        write!(f, ", ").unwrap();
                    }
                    write!(f,"{}: {}", args[k],
                           match argu {
                               "const unsigned char *" => "*const u8",
                               "unsigned char *" => "*mut u8",
                               "unsigned long long *" => "*mut c_ulonglong",
                               "unsigned long long" => "c_ulonglong",
                               a => panic!("unknown type {:?}", a)
                           }).unwrap();
                    k+=1
                }
                let typ = captures.at(1).unwrap();
                if typ == "int" {
                    writeln!(f, ") -> c_int;").unwrap();
                } else if typ == "" {
                    writeln!(f, ");").unwrap();
                } else {
                    panic!("typ : {:?}", typ);
                }
                
            } else if i != "#define TWEETNACL_H" && i != "#endif" {
                panic!("line: {:?}", i);
            }
        }
        if in_extern_block {
            writeln!(f,"}}").unwrap();
        }


    }
    gcc::Config::new()
        .file(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("tweetnacl.c"))
        .compile("libtweetnacl.a");

    println!("cargo:rustc-flags=-l static=tweetnacl")
}


fn check_name(n:&str) -> bool {
    !(n.chars().any(|x| x<'A' || x> 'Z'))
}
