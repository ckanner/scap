use super::*;

use scap_object_store::Stored;
use std::collections::BTreeMap;
use std::sync::Mutex;

pub(super) use crate::tests::deadline;

#[derive(Clone, Debug)]
pub(super) struct Call {
    pub put: bool,
    pub key: String,
    pub bytes: Vec<u8>,
    pub condition: Option<String>,
}

#[derive(Clone)]
pub(super) enum Fault {
    Before(StoreError),
    AfterPut,
    EmptyEtag,
    Run(Arc<dyn Fn() + Send + Sync>),
    Replace {
        key: String,
        bytes: Vec<u8>,
        preserve_etag: bool,
    },
}

#[derive(Clone)]
struct Cut {
    at: Option<usize>,
    put: bool,
    key: String,
    field: Option<(String, String)>,
    skip: usize,
    fault: Fault,
}

#[derive(Clone, Default)]
struct State {
    values: BTreeMap<String, Stored>,
    serial: u64,
    calls: Vec<Call>,
    cut: Option<Cut>,
}

#[derive(Default)]
pub(super) struct Memory {
    state: Mutex<State>,
}

impl Memory {
    pub fn fork(&self) -> Arc<Self> {
        let mut state = self.state.lock().unwrap().clone();
        state.calls.clear();
        state.cut = None;
        Arc::new(Self {
            state: Mutex::new(state),
        })
    }

    pub fn calls(&self) -> Vec<Call> {
        self.state.lock().unwrap().calls.clone()
    }
    pub fn clear_calls(&self) {
        self.state.lock().unwrap().calls.clear();
    }
    pub fn get_value(&self, key: &str) -> Option<Stored> {
        self.state.lock().unwrap().values.get(key).cloned()
    }
    pub fn remove(&self, key: &str) {
        self.state.lock().unwrap().values.remove(key);
    }
    pub fn set(&self, key: &str, bytes: Vec<u8>) {
        let mut state = self.state.lock().unwrap();
        state.serial += 1;
        let etag = state.serial.to_string();
        state.values.insert(key.into(), Stored { bytes, etag });
    }
    pub fn fail_at(&self, at: usize, fault: Fault) {
        let mut state = self.state.lock().unwrap();
        let at = state.calls.len() + at;
        state.cut = Some(Cut {
            at: Some(at),
            put: false,
            key: String::new(),
            field: None,
            skip: 0,
            fault,
        });
    }
    pub fn cut(
        &self,
        put: bool,
        key: &str,
        field: Option<(&str, &str)>,
        skip: usize,
        fault: Fault,
    ) {
        self.state.lock().unwrap().cut = Some(Cut {
            at: None,
            put,
            key: key.into(),
            field: field.map(|(a, b)| (a.into(), b.into())),
            skip,
            fault,
        });
    }
    fn fault(state: &mut State, call: Call) -> Option<Fault> {
        state.calls.push(call.clone());
        let number = state.calls.len();
        let cut = state.cut.as_mut()?;
        let matches = if let Some(at) = cut.at {
            at == number
        } else {
            cut.put == call.put
                && cut.key == call.key
                && cut.field.as_ref().is_none_or(|(field, value)| {
                    serde_json::from_slice::<serde_json::Value>(&call.bytes).unwrap()[field]
                        == value.as_str()
                })
        };
        if !matches {
            return None;
        }
        if cut.skip != 0 {
            cut.skip -= 1;
            return None;
        }
        state.cut.take().map(|cut| cut.fault)
    }
}

impl Objects for Memory {
    fn get(&self, key: &str, max_bytes: usize, until: Instant) -> Result<Stored, StoreError> {
        if Instant::now() >= until {
            return Err(StoreError::Unknown);
        }
        let mut state = self.state.lock().unwrap();
        let fault = Self::fault(
            &mut state,
            Call {
                put: false,
                key: key.into(),
                bytes: vec![],
                condition: None,
            },
        );
        if let Some(Fault::Before(error)) = fault {
            return Err(error);
        }
        if let Some(Fault::Run(action)) = &fault {
            drop(state);
            action();
            state = self.state.lock().unwrap();
        }
        if let Some(Fault::Replace {
            key: target,
            bytes,
            preserve_etag,
        }) = &fault
        {
            state.serial += 1;
            let etag = if *preserve_etag {
                state.values[target].etag.clone()
            } else {
                state.serial.to_string()
            };
            state.values.insert(
                target.clone(),
                Stored {
                    bytes: bytes.clone(),
                    etag,
                },
            );
        }
        let mut value = state.values.get(key).cloned().ok_or(StoreError::Missing)?;
        if value.bytes.len() > max_bytes {
            return Err(StoreError::Limit);
        }
        if matches!(fault, Some(Fault::EmptyEtag)) {
            value.etag.clear();
        }
        Ok(value)
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        until: Instant,
    ) -> Result<String, StoreError> {
        if Instant::now() >= until {
            return Err(StoreError::Unknown);
        }
        let mut state = self.state.lock().unwrap();
        let expected = match condition {
            Condition::Absent => "*",
            Condition::Match(etag) => etag,
        };
        let fault = Self::fault(
            &mut state,
            Call {
                put: true,
                key: key.into(),
                bytes: bytes.to_vec(),
                condition: Some(expected.into()),
            },
        );
        if let Some(Fault::Before(error)) = fault {
            return Err(error);
        }
        if let Some(Fault::Run(action)) = &fault {
            drop(state);
            action();
            state = self.state.lock().unwrap();
        }
        let old = state.values.get(key);
        match condition {
            Condition::Absent if old.is_some() => {
                return Err(if matches!(fault, Some(Fault::AfterPut)) {
                    StoreError::Unknown
                } else {
                    StoreError::Conflict
                })
            }
            Condition::Match(etag) if old.is_none_or(|stored| stored.etag != etag) => {
                return Err(if matches!(fault, Some(Fault::AfterPut)) {
                    StoreError::Unknown
                } else {
                    StoreError::Conflict
                });
            }
            _ => {}
        }
        state.serial += 1;
        let etag = state.serial.to_string();
        state.values.insert(
            key.into(),
            Stored {
                bytes: bytes.to_vec(),
                etag: etag.clone(),
            },
        );
        if matches!(fault, Some(Fault::AfterPut)) {
            return Err(StoreError::Unknown);
        }
        Ok(etag)
    }
}

pub(super) const CREATOR: Caller = Caller {
    principal: 7,
    provision: true,
};

pub(super) fn catalogue(objects: Arc<Memory>) -> Catalogue {
    Catalogue::new(objects, 1, 2, 10, crate::tests::test_options()).unwrap()
}

pub(super) fn input(name: &str, operation: u64, previous: Option<u64>) -> PrepareCreate {
    PrepareCreate {
        name: name.into(),
        operation,
        expected_name_revision: previous,
        options: CreateOptions::default(),
    }
}

pub(super) fn prepared() -> (Arc<Memory>, Catalogue, Creation) {
    let objects = Arc::new(Memory::default());
    let catalogue = catalogue(objects.clone());
    let creation = catalogue
        .prepare(CREATOR, &input("shared name", 1, None), deadline())
        .unwrap()
        .creation;
    (objects, catalogue, creation)
}

pub(super) fn stage(phase: CreationPhase) -> (Arc<Memory>, Catalogue, Creation) {
    let (objects, catalogue, creation) = prepared();
    let (key, field, value) = match phase {
        CreationPhase::Reserved => (
            format::head_key(&creation.scope),
            "lifecycle",
            "provisioning",
        ),
        CreationPhase::Provisioning => (catalogue.binding_key(&creation.name), "state", "bound"),
        CreationPhase::Bound => (format::head_key(&creation.scope), "lifecycle", "ready"),
        CreationPhase::Ready => {
            catalogue
                .resume_create(CREATOR, &creation, deadline())
                .unwrap();
            return (objects, catalogue, creation);
        }
        _ => panic!("unsupported fixture stage"),
    };
    objects.cut(
        true,
        &key,
        Some((field, value)),
        0,
        Fault::Before(StoreError::Unknown),
    );
    assert_eq!(
        catalogue.resume_create(CREATOR, &creation, deadline()),
        Err(CatalogueError::Unknown)
    );
    assert_eq!(
        catalogue
            .inspect_create_operation(CREATOR, creation.operation, deadline())
            .unwrap()
            .phase,
        phase
    );
    (objects, catalogue, creation)
}

pub(super) fn abort(creation: &Creation) -> AbortCreate {
    AbortCreate {
        creation: creation.clone(),
        operation: 20,
        expected_name_revision: creation.expected_name_revision.unwrap_or(0) + 1,
        nonce: 21,
    }
}

pub(super) fn delete(creation: &Creation) -> DeleteNamed {
    DeleteNamed {
        creation: creation.clone(),
        operation: 30,
        expected_name_revision: creation.expected_name_revision.unwrap_or(0) + 2,
        expected_head_revision: 2,
        nonce: 31,
    }
}

pub(super) fn descriptor(catalogue: &Catalogue, creation: &Creation) -> Source {
    catalogue.descriptor(creation, deadline()).unwrap()
}

#[path = "boundary_tests.rs"]
mod boundary_tests;
#[path = "discovery_tests.rs"]
pub(super) mod discovery_tests;
#[path = "fault_tests.rs"]
mod fault_tests;
#[path = "protocol_tests.rs"]
mod protocol_tests;
#[path = "records_tests.rs"]
mod records_tests;
#[path = "recovery_tests.rs"]
mod recovery_tests;

#[test]
fn named_creation_is_resumable_and_resolves_only_ready() {
    let objects = Arc::new(crate::tests::Memory::default());
    let catalogue = Catalogue::new(objects, 1, 2, 10, crate::tests::test_options()).unwrap();
    let caller = Caller {
        principal: 7,
        provision: true,
    };
    let input = PrepareCreate {
        name: "my database".into(),
        operation: 1,
        expected_name_revision: None,
        options: CreateOptions::default(),
    };
    let prepared = catalogue
        .prepare(caller, &input, crate::tests::deadline())
        .unwrap();
    assert_eq!(
        catalogue
            .inspect_create_operation(caller, 1, crate::tests::deadline())
            .unwrap()
            .phase,
        CreationPhase::NotReserved
    );
    assert_eq!(
        catalogue.resolve(caller, &input.name, crate::tests::deadline()),
        Err(CatalogueError::NotFound)
    );
    let progress = catalogue
        .resume_create(caller, &prepared.creation, crate::tests::deadline())
        .unwrap();
    assert_eq!(progress.phase, CreationPhase::Ready);
    assert_eq!(progress.binding_revision, Some(2));
    assert_eq!(progress.head_revision, Some(2));
    let named = catalogue
        .resolve(caller, &input.name, crate::tests::deadline())
        .unwrap();
    assert_eq!(named.creation, prepared.creation);
    assert_eq!(named.head.lifecycle, Lifecycle::Ready);
    assert!(!named.head.active);
    assert_eq!(
        catalogue
            .resume_create(caller, &prepared.creation, crate::tests::deadline())
            .unwrap(),
        progress
    );
}
