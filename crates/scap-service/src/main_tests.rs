use super::*;

#[test]
fn process_exit_reports_the_original_startup_result() {
    assert_eq!(exit(Ok(())), ExitCode::SUCCESS);
    assert_eq!(
        exit(Err(scap_service::Failure::new("INSTANCE_REUSED"))),
        ExitCode::FAILURE
    );
}
