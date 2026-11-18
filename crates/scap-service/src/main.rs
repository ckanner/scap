use std::process::ExitCode;

pub fn main() -> std::process::ExitCode {
    exit(scap_service::daemon::entry(
        std::env::args_os().skip(1).collect(),
    ))
}

fn exit(result: Result<(), scap_service::Failure>) -> ExitCode {
    if let Err(error) = result {
        eprintln!("scapd: {}", error.code);
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
