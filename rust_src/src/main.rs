#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_interface;

use clap::Parser;
use std::sync::{Arc, Mutex};
use rust_cpg_generator::CpgCompilerCallbacks;
use rust_cpg_generator::cpg::nodes::CpgGraph;
use std::process::Command;
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input Rust file
    #[arg(short, long)]
    input: String,

    /// Output JSON file
    #[arg(short, long, default_value = "cpg.json")]
    output: String,
    
    /// Sysroot (optional)
    #[arg(long)]
    sysroot: Option<String>,

    /// Extra rustc args (repeatable)
    #[arg(long, action = clap::ArgAction::Append, allow_hyphen_values = true)]
    rustc_arg: Vec<String>,
}

fn main() {
    env_logger::init();
    let args = Args::parse();

    // 构造 rustc 参数
    // 我们主要进行分析，不需要生成代码，所以使用 -Z no-codegen (需 nightly) 
    // 或者 --emit=metadata
    let mut rustc_args = vec![
        "rustc".to_string(),
        args.input.clone(),
        "--crate-type".to_string(),
        "lib".to_string(),
    ];

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

    let graph = Arc::new(Mutex::new(CpgGraph::new()));
    let mut callbacks = CpgCompilerCallbacks::new(graph.clone());
    
    log::info!("Running rustc analysis on {}", args.input);
    
    // 运行编译器驱动
    let exit_code = rustc_driver::catch_with_exit_code(move || {
        rustc_driver::run_compiler(&rustc_args, &mut callbacks);
    });

    if exit_code == 0 {
        // 序列化并保存图数据
        match std::fs::File::create(&args.output) {
            Ok(file) => {
                let graph = graph.lock().unwrap();
                if let Err(e) = serde_json::to_writer_pretty(file, &*graph) {
                    eprintln!("Failed to write output: {}", e);
                } else {
                    println!("CPG successfully generated at {}", args.output);
                }
            }
            Err(e) => eprintln!("Failed to create output file: {}", e),
        }
    } else {
        eprintln!("Analysis failed with exit code {:?}", exit_code);
        std::process::exit(1);
    }
}
