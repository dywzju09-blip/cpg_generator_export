#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_interface;

use rust_cpg_generator::cpg::nodes::CpgGraph;
use rust_cpg_generator::CpgCompilerCallbacks;
use std::process::Command;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct Args {
    input: String,
    output: String,
    sysroot: Option<String>,
    rustc_arg: Vec<String>,
}

fn print_usage() {
    eprintln!(
        "Usage: rust-cpg-generator --input <path> [--output <path>] [--sysroot <path>] [--rustc-arg <arg>]..."
    );
}

fn parse_args() -> Result<Args, String> {
    let mut input = None;
    let mut output = String::from("cpg.json");
    let mut sysroot = None;
    let mut rustc_arg = Vec::new();
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-i" | "--input" => {
                input = Some(
                    args.next()
                        .ok_or_else(|| String::from("--input requires a value"))?,
                );
            }
            "-o" | "--output" => {
                output = args
                    .next()
                    .ok_or_else(|| String::from("--output requires a value"))?;
            }
            "--sysroot" => {
                sysroot = Some(
                    args.next()
                        .ok_or_else(|| String::from("--sysroot requires a value"))?,
                );
            }
            "--rustc-arg" => {
                rustc_arg.push(
                    args.next()
                        .ok_or_else(|| String::from("--rustc-arg requires a value"))?,
                );
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("{}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => return Err(format!("unrecognized argument: {}", arg)),
        }
    }

    Ok(Args {
        input: input.ok_or_else(|| String::from("--input is required"))?,
        output,
        sysroot,
        rustc_arg,
    })
}

#[cfg(legacy_rustc_private_api)]
fn run_compiler_and_succeeded(rustc_args: &[String], callbacks: &mut CpgCompilerCallbacks) -> bool {
    let exit_code = rustc_driver::catch_with_exit_code(|| {
        rustc_driver::run_compiler(rustc_args, callbacks, None, None, None)
    });
    exit_code == 0
}

#[cfg(not(legacy_rustc_private_api))]
fn run_compiler_and_succeeded(rustc_args: &[String], callbacks: &mut CpgCompilerCallbacks) -> bool {
    let exit_code = rustc_driver::catch_with_exit_code(|| {
        rustc_driver::run_compiler(rustc_args, callbacks);
    });
    exit_code == std::process::ExitCode::SUCCESS
}

fn main() {
    let args = match parse_args() {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("{}", err);
            print_usage();
            std::process::exit(2);
        }
    };
    let has_explicit_crate_type = args
        .rustc_arg
        .iter()
        .any(|arg| arg == "--crate-type" || arg.starts_with("--crate-type="));

    // 构造 rustc 参数
    // 我们主要进行分析，不需要生成代码，所以使用 -Z no-codegen (需 nightly)
    // 或者 --emit=metadata
    let mut rustc_args = vec!["rustc".to_string(), args.input.clone()];

    // 自动获取 sysroot
    if let Some(sysroot) = args.sysroot {
        rustc_args.push("--sysroot".to_string());
        rustc_args.push(sysroot);
    } else {
        let out = Command::new("rustc")
            .arg("--print")
            .arg("sysroot")
            .output()
            .ok();
        if let Some(out) = out {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                rustc_args.push("--sysroot".to_string());
                rustc_args.push(s);
            }
        }
    }

    if !args.rustc_arg.is_empty() {
        rustc_args.extend(args.rustc_arg.clone());
    }
    if !has_explicit_crate_type {
        rustc_args.push("--crate-type".to_string());
        rustc_args.push("lib".to_string());
    }

    let graph = Arc::new(Mutex::new(CpgGraph::new()));
    let mut callbacks = CpgCompilerCallbacks::new(graph.clone());

    log::info!("Running rustc analysis on {}", args.input);

    if run_compiler_and_succeeded(&rustc_args, &mut callbacks) {
        match std::fs::File::create(&args.output) {
            Ok(file) => {
                let graph = graph.lock().unwrap();
                if let Err(e) = graph.write_pretty_json(file) {
                    eprintln!("Failed to write output: {}", e);
                } else {
                    println!("CPG successfully generated at {}", args.output);
                }
            }
            Err(e) => eprintln!("Failed to create output file: {}", e),
        }
    } else {
        eprintln!("Analysis failed");
        std::process::exit(1);
    }
}
