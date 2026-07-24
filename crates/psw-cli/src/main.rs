#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process;

use psw_cli::{doctor_vault, render_text_report};

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let command = args.first().map(String::as_str);
    match command {
        Some("doctor") => run_doctor(&args[1..]),
        _ => {
            eprintln!("usage: psw doctor [--json] <vault-path>");
            process::exit(2);
        }
    }
}

fn run_doctor(args: &[String]) {
    let mut json = false;
    let mut path = None;

    for arg in args {
        if arg == "--json" {
            json = true;
        } else if path.is_none() {
            path = Some(PathBuf::from(arg));
        } else {
            eprintln!("usage: psw doctor [--json] <vault-path>");
            process::exit(2);
        }
    }

    let Some(path) = path else {
        eprintln!("usage: psw doctor [--json] <vault-path>");
        process::exit(2);
    };

    let report = doctor_vault(&path);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize doctor report")
        );
    } else {
        print!("{}", render_text_report(&report));
    }

    if !report.is_usable() {
        process::exit(1);
    }
}
