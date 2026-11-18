use super::*;

#[test]
fn explicit_quota_choices_override_both_kinds_of_configured_default() {
    for default in [
        DatabaseQuota { max_bytes: None },
        DatabaseQuota {
            max_bytes: Some(8192),
        },
    ] {
        for (quota, expected) in [
            (QuotaChoice::Default, default.clone()),
            (QuotaChoice::Unlimited, DatabaseQuota { max_bytes: None }),
            (
                QuotaChoice::Limited { max_bytes: 4096 },
                DatabaseQuota {
                    max_bytes: Some(4096),
                },
            ),
        ] {
            // An added enum variant must receive a conscious codebook/test
            // update instead of silently inheriting the default tail.
            let (QuotaChoice::Default | QuotaChoice::Unlimited | QuotaChoice::Limited { .. }) =
                &quota;
            assert_eq!(CreateOptions { quota }.effective_quota(&default), expected);
        }
    }
}
