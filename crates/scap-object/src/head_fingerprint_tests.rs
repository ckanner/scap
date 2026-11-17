//! Whole-body hash equivalence across representative authority records.

use super::*;
use crate::format::{Permission, MAX_PRINCIPALS};
use crate::snapshot_format::{SnapshotEntry, SnapshotLimits, SnapshotPoint, SnapshotRef};
use crate::tests::{deadline, fixture};

pub(super) fn heads() -> [Head; 2] {
    let (_, database) = fixture();
    let small = database.read_head(deadline()).unwrap().head;
    let mut large = small.clone();
    large.policy = (1..=MAX_PRINCIPALS as u64)
        .map(|principal| Permission {
            principal,
            read: true,
            write: true,
            admin: principal == 7,
        })
        .collect();
    small.validate().unwrap();
    large.validate().unwrap();
    [small, large]
}

pub(super) fn legacy(head: &Head) -> String {
    digest(&serde_json::to_vec(head).unwrap())
}

pub(super) fn streamed(head: &Head) -> [u8; 32] {
    let mut hasher = Sha256::new();
    serde_json::to_writer(&mut hasher, head).unwrap();
    hasher.finalize().into()
}

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn fingerprints_preserve_the_complete_canonical_body() {
    let [small, mut populated] = heads();
    populated.format = 9;
    populated.snapshots = Some(vec![SnapshotEntry {
        reference: SnapshotRef {
            creator: 7,
            operation: 33,
            capture_serial: 2,
            descriptor_hash: digest(b"retained descriptor"),
        },
        label: "escaped \\\" and 中文 snapshot".into(),
        point: SnapshotPoint {
            data_root: populated.data_root.clone(),
            page_count: 0,
            sequence: 0,
            source_revision: 1,
        },
    }]);
    populated.snapshot_limits = Some(SnapshotLimits::default());
    populated.restore_origin = Some(None);
    populated.head_serial = 2;
    populated.validate().unwrap();
    for original in [small, populated] {
        let fingerprint = head_fingerprint(&original);
        assert_eq!(hex(fingerprint), legacy(&original));
        assert_eq!(streamed(&original), fingerprint);
        for field in 0..4 {
            let mut changed = original.clone();
            match field {
                0 => changed.policy[0].write = !changed.policy[0].write,
                1 => changed.windows[0].result_bytes += 1,
                2 => changed.owner_instance += 1,
                _ => changed.auth_epoch += 1,
            }
            assert_ne!(head_fingerprint(&changed), fingerprint);
            assert_eq!(hex(head_fingerprint(&changed)), legacy(&changed));
        }
    }
}
