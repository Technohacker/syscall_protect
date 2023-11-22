use std::{env, error::Error, fs, process};

fn try_or_error<T, E: Error>(res: Result<T, E>, msg: &'static str) -> Result<T, String> {
    res.map_err(|x| format!("{msg}: {x}"))
}

fn main() -> Result<(), String> {
    let mut args = env::args();

    let prog_name = args.next().expect("Missing program name");

    if args.len() < 2 {
        eprintln!("Usage: {prog_name} <policy file> <program> [args...]");
        process::exit(1);
    }

    let policy_path = args.next().expect("Missing policy path?");
    let policy = try_or_error(
        fs::read(policy_path),
        "Failed to read policy file",
    )?;

    try_or_error(
        fs::write("/proc/syscall_protect/start", policy),
        "Failed to open syscall_protect start, is the module loaded?",
    )?;

    let mut args = args.peekable();
    let err = exec::execvp(args.peek().expect("No program?").clone(), args);

    panic!("Failed to swap program! {err}");
}
