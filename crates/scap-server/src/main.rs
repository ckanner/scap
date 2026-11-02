fn main() -> Result<(), String> {
    scap_server::command(std::env::args_os().skip(1)).map_err(|error| error.code)
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
