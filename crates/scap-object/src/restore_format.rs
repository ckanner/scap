//! Restore provenance is immutable after the private Copying -> Copied transition.

use serde::{Deserialize, Deserializer, Serialize};

use crate::format::{
    digest, encode_object, hash_valid, Envelope, FormatError, Head, Lifecycle, Manifest, Payload,
    RequestIndex, MAX_PAGES,
};
use crate::snapshot_format::valid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreOrigin {
    pub descriptor_hash: String,
    pub phase: RestoreCopyPhase,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RestoreCopyPhase {
    Copying {},
    Copied {
        completion_hash: String,
        data_root: String,
        page_count: u32,
    },
}

pub(crate) fn present_origin<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<RestoreOrigin>>, D::Error> {
    Option::<RestoreOrigin>::deserialize(deserializer).map(Some)
}

pub(crate) fn validate_head(head: &Head) -> Result<(), FormatError> {
    let Some(Some(origin)) = &head.restore_origin else {
        return Ok(());
    };
    let creation = head.creation.as_ref().ok_or(FormatError::Invalid)?;
    valid(
        hash_valid(&origin.descriptor_hash) && origin.descriptor_hash == creation.descriptor_hash,
    )?;
    match &origin.phase {
        RestoreCopyPhase::Copying {} => {
            valid(matches!(
                head.lifecycle,
                Lifecycle::Provisioning | Lifecycle::Deleted
            ))?;
            valid(!head.active && head.sequence == 0 && head.request_epoch == 1)?;
            valid(head.windows[0].count == 0 && head.windows[0].result_bytes == 0)?;
            valid(
                head.data_root
                    == initial_hash(
                        head,
                        Payload::Manifest(Manifest {
                            page_count: 0,
                            root: None,
                        }),
                    ),
            )?;
            valid(
                head.windows[0].root
                    == initial_hash(
                        head,
                        Payload::Index(RequestIndex::Leaf {
                            epoch: 1,
                            entries: Vec::new(),
                        }),
                    ),
            )
        }
        RestoreCopyPhase::Copied {
            completion_hash,
            data_root,
            page_count,
        } => {
            valid(
                hash_valid(completion_hash) && hash_valid(data_root) && *page_count <= MAX_PAGES,
            )?;
            // A subsequent committed SQL transaction may replace the current
            // root. Provenance never becomes a second retained payload edge.
            valid(head.sequence != 0 || head.data_root == *data_root)
        }
    }
}

fn initial_hash(head: &Head, payload: Payload) -> String {
    let bytes = encode_object(&Envelope {
        format: 2,
        scope: head.scope.clone(),
        payload,
    })
    .expect("HEAD validated Scope and bounded empty object");
    digest(&bytes)
}
