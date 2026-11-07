pub fn main() -> std::process::ExitCode {
    scap_service::daemon::entry(std::env::args_os().skip(1).collect())
}
