#[test]
fn main_reports_invalid_test_runner_arguments() {
    assert!(super::main().is_err());
}
