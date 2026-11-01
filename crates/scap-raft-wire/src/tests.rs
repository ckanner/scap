use super::*;
use protobuf::ProtobufEnum;
use raft::eraftpb::{Entry, EntryType, Snapshot};

fn scope() -> Scope {
    Scope {
        cluster_id: 17,
        cell_id: 29,
        cell_incarnation: 3,
        node_id: 1,
    }
}

fn limits() -> Limits {
    Limits {
        max_payload_bytes: 4096,
        max_entries: 16,
        max_fields: 128,
        max_certificate_bytes: 4096,
        max_bindings: 8,
    }
}

fn certificate() -> CertificateIdentity {
    CertificateIdentity {
        fingerprint: [2; 32],
        not_before: 100,
        not_after: 200,
    }
}

fn bindings() -> Vec<Binding> {
    vec![Binding {
        node_id: 2,
        fingerprint: certificate().fingerprint,
    }]
}

fn policy() -> Policy {
    Policy::new(scope(), vec![1, 2, 3], bindings(), limits()).unwrap()
}

fn message(kind: MessageType) -> Message {
    let mut message = Message::default();
    message.set_msg_type(kind);
    message.from = 2;
    message.to = 1;
    message.term = 3;
    message
}

fn wrap(message: &Message) -> Envelope {
    Envelope {
        version: VERSION,
        codec: CODEC,
        cluster_id: scope().cluster_id,
        cell_id: scope().cell_id,
        cell_incarnation: scope().cell_incarnation,
        from_node: message.from,
        to_node: message.to,
        payload: message.write_to_bytes().unwrap(),
    }
}

fn envelope() -> Envelope {
    wrap(&message(MessageType::MsgHeartbeat))
}

fn authorize(envelope: Envelope) -> Result<AuthorizedMessage, Error> {
    policy().authorize(certificate(), 150, envelope)
}

fn hexadecimal(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn envelope_has_a_fixed_golden_layout_and_preserves_every_field() {
    let original = Envelope {
        version: 1,
        codec: 1,
        cluster_id: 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100,
        cell_id: 0x1f1e_1d1c_1b1a_1918_1716_1514_1312_1110,
        cell_incarnation: 0x2726_2524_2322_2120,
        from_node: 0x3736_3534_3332_3130,
        to_node: 0x4746_4544_4342_4140,
        payload: vec![0xa1, 0xff],
    };
    let expected = hexadecimal(concat!(
        "5343415052504331",
        "01000000",
        "01000000",
        "000102030405060708090a0b0c0d0e0f",
        "101112131415161718191a1b1c1d1e1f",
        "2021222324252627",
        "3031323334353637",
        "4041424344454647",
        "0200000000000000",
        "a1ff"
    ));
    assert_eq!(HEADER_BYTES, 80);
    let encoded = encode_envelope(&original, 82).unwrap();
    assert_eq!(encoded, expected);
    assert_eq!(decode_envelope(&encoded, 82).unwrap(), original);
    let mut empty = original;
    empty.payload.clear();
    assert_eq!(
        decode_envelope(&encode_envelope(&empty, 80).unwrap(), 80).unwrap(),
        empty
    );
}

#[test]
fn envelope_bounds_magic_declared_length_and_trailing_bytes_fail_closed() {
    let original = envelope();
    assert_eq!(
        encode_envelope(&original, 79),
        Err(Error::Limit("peer envelope"))
    );
    assert_eq!(
        encode_envelope(&original, 80),
        Err(Error::Limit("peer envelope"))
    );
    let encoded = encode_envelope(&original, 4096).unwrap();
    assert_eq!(
        decode_envelope(&encoded, encoded.len() - 1),
        Err(Error::Limit("peer envelope"))
    );
    for len in 0..HEADER_BYTES {
        assert_eq!(
            decode_envelope(&encoded[..len], 4096),
            Err(Error::Malformed("peer envelope header"))
        );
    }
    let mut changed = encoded.clone();
    changed[0] ^= 1;
    assert_eq!(
        decode_envelope(&changed, 4096),
        Err(Error::Malformed("peer envelope header"))
    );
    changed = encoded.clone();
    changed[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        decode_envelope(&changed, 4096),
        Err(Error::Malformed("peer envelope length"))
    );
    changed = encoded;
    changed.push(0);
    assert_eq!(
        decode_envelope(&changed, 4096),
        Err(Error::Malformed("peer envelope length"))
    );
}

#[test]
fn policy_configuration_validates_every_identity_limit_and_binding() {
    for field in 0..5 {
        let mut changed = limits();
        match field {
            0 => changed.max_payload_bytes = 0,
            1 => changed.max_entries = 0,
            2 => changed.max_fields = 0,
            3 => changed.max_certificate_bytes = 0,
            _ => changed.max_bindings = 0,
        }
        assert!(matches!(
            Policy::new(scope(), vec![1, 2, 3], bindings(), changed),
            Err(Error::Invalid("zero wire limit"))
        ));
    }
    for field in 0..4 {
        let mut changed = scope();
        match field {
            0 => changed.cluster_id = 0,
            1 => changed.cell_id = 0,
            2 => changed.cell_incarnation = 0,
            _ => changed.node_id = 0,
        }
        assert!(matches!(
            Policy::new(changed, vec![1, 2, 3], bindings(), limits()),
            Err(Error::Invalid("zero scope identity"))
        ));
    }
    for members in [vec![], (1..=9).collect()] {
        assert!(matches!(
            Policy::new(scope(), members, bindings(), limits()),
            Err(Error::Limit("bootstrap members"))
        ));
    }
    for members in [vec![1, 0], vec![1, 1]] {
        assert!(matches!(
            Policy::new(scope(), members, bindings(), limits()),
            Err(Error::Invalid("bootstrap member identity"))
        ));
    }
    assert!(matches!(
        Policy::new(scope(), vec![2, 3], bindings(), limits()),
        Err(Error::Invalid("local node is not a bootstrap member"))
    ));
    assert!(matches!(
        Policy::new(scope(), vec![1, 2, 3], vec![bindings()[0]; 9], limits()),
        Err(Error::Limit("certificate bindings"))
    ));
    assert!(matches!(
        Policy::new(scope(), vec![1, 3], bindings(), limits()),
        Err(Error::Invalid("certificate node is not a bootstrap member"))
    ));
    assert!(matches!(
        Policy::new(scope(), vec![1, 2, 3], vec![bindings()[0]; 2], limits()),
        Err(Error::Invalid("duplicate certificate fingerprint"))
    ));
    let empty = Policy::new(scope(), vec![1, 2, 3], vec![], limits()).unwrap();
    assert_eq!(
        empty.authorize(certificate(), 150, envelope()),
        Err(Error::Unauthorized)
    );
    let p = policy();
    assert_eq!(p.scope(), scope());
    assert_eq!(p.limits(), limits());
    assert_eq!(p.members(), &BTreeSet::from([1, 2, 3]));
    assert_eq!(p.revision(), 1);
}

#[test]
fn successful_authorization_returns_immutable_message_and_original_payload() {
    let request = envelope();
    let accepted = authorize(request.clone()).unwrap();
    assert_eq!(accepted.peer_node(), 2);
    assert_eq!(accepted.revision(), 1);
    assert_eq!(accepted.certificate(), certificate());
    assert_eq!(accepted.envelope(), &request);
    assert_eq!(accepted.message(), &message(MessageType::MsgHeartbeat));
    assert_eq!(policy().revalidate(&accepted, 150), Ok(()));
    assert_eq!(accepted.into_message(), message(MessageType::MsgHeartbeat));
}

#[test]
fn untrusted_version_route_and_certificate_are_rejected_before_payload_decode() {
    for field in 0..9 {
        let mut request = envelope();
        request.payload = vec![0xff];
        let mut cert = certificate();
        match field {
            0 => request.version += 1,
            1 => request.codec += 1,
            2 => request.cluster_id += 1,
            3 => request.cell_id += 1,
            4 => request.cell_incarnation += 1,
            5 => request.to_node += 1,
            6 => request.from_node = 1,
            7 => request.from_node = 0,
            _ => cert.fingerprint = [3; 32],
        }
        let expected = if field < 2 {
            Error::Unsupported("peer wire version")
        } else {
            Error::Unauthorized
        };
        assert_eq!(policy().authorize(cert, 150, request), Err(expected));
    }
    for now in [99, 201] {
        assert_eq!(
            policy().authorize(certificate(), now, envelope()),
            Err(Error::CertificateTime)
        );
    }
    for now in [100, 200] {
        assert!(policy().authorize(certificate(), now, envelope()).is_ok());
    }
}

#[test]
fn rotation_and_revocation_recheck_queued_and_existing_connection_messages() {
    let mut p = policy();
    let accepted = p.authorize(certificate(), 150, envelope()).unwrap();
    assert_eq!(p.revalidate(&accepted, 201), Err(Error::CertificateTime));
    assert_eq!(
        p.replace_bindings(vec![Binding {
            node_id: 99,
            fingerprint: [9; 32]
        }]),
        Err(Error::Invalid("certificate node is not a bootstrap member"))
    );
    assert_eq!(p.revision(), 1);
    assert_eq!(p.revalidate(&accepted, 150), Ok(()));
    p.limits.max_entries -= 1;
    assert_eq!(p.revalidate(&accepted, 150), Err(Error::PolicyChanged));
    p.limits = limits();
    let different_members = Policy::new(scope(), vec![1, 2, 4], bindings(), limits()).unwrap();
    assert_eq!(
        different_members.revalidate(&accepted, 150),
        Err(Error::PolicyChanged)
    );
    let rotated = CertificateIdentity {
        fingerprint: [4; 32],
        ..certificate()
    };
    let overlap = vec![
        bindings()[0],
        Binding {
            node_id: 2,
            fingerprint: rotated.fingerprint,
        },
    ];
    assert_eq!(p.replace_bindings(overlap), Ok(2));
    assert_eq!(p.revalidate(&accepted, 150), Err(Error::PolicyChanged));
    assert!(p.authorize(certificate(), 150, envelope()).is_ok());
    assert!(p.authorize(rotated, 150, envelope()).is_ok());
    p.replace_bindings(vec![Binding {
        node_id: 2,
        fingerprint: rotated.fingerprint,
    }])
    .unwrap();
    assert_eq!(
        p.authorize(certificate(), 150, envelope()),
        Err(Error::Unauthorized)
    );
    assert!(p.authorize(rotated, 150, envelope()).is_ok());
    p.replace_bindings(vec![]).unwrap();
    assert_eq!(
        p.authorize(rotated, 150, envelope()),
        Err(Error::Unauthorized)
    );
    p.revision = u64::MAX;
    assert_eq!(
        p.replace_bindings(bindings()),
        Err(Error::RevisionExhausted)
    );
    assert_eq!(p.revision(), u64::MAX);
    assert_eq!(
        p.authorize(certificate(), 150, envelope()),
        Err(Error::Unauthorized)
    );
}

#[test]
fn only_pinned_network_message_kinds_are_admitted() {
    for value in 0..=18 {
        let kind = MessageType::from_i32(value).unwrap();
        let result = authorize(wrap(&message(kind)));
        if [0, 1, 2, 10, 11, 12, 13, 15, 16].contains(&value) {
            assert_eq!(
                result,
                Err(Error::Unsupported("local or forwarded request"))
            );
        } else {
            assert_eq!(result.unwrap().message().get_msg_type(), kind);
        }
    }
}

#[test]
fn endpoints_payload_and_decoded_object_budgets_are_independent() {
    for field in 0..2 {
        let mut inner = message(MessageType::MsgHeartbeat);
        if field == 0 {
            inner.from = 3;
        } else {
            inner.to = 3;
        }
        let mut request = envelope();
        request.payload = inner.write_to_bytes().unwrap();
        assert_eq!(
            authorize(request),
            Err(Error::Malformed("Raft endpoint mismatch"))
        );
    }
    let mut p = policy();
    p.limits.max_payload_bytes = 1;
    assert_eq!(
        p.authorize(certificate(), 150, envelope()),
        Err(Error::Limit("Raft payload"))
    );
    p = policy();
    p.limits.max_fields = 1;
    assert_eq!(
        p.authorize(certificate(), 150, envelope()),
        Err(Error::Limit("Raft fields"))
    );
    p = policy();
    p.limits.max_entries = 1;
    let mut inner = message(MessageType::MsgAppend);
    inner.mut_entries().push(Entry::default());
    inner.mut_entries().push(Entry::default());
    assert_eq!(
        p.authorize(certificate(), 150, wrap(&inner)),
        Err(Error::Limit("Raft entries"))
    );
    // Correct framing with a wrong wire type for the known term field reaches
    // the real generated decoder and must still fail there.
    let mut request = envelope();
    request.payload.extend_from_slice(&[0x22, 0x00]);
    assert_eq!(authorize(request), Err(Error::Malformed("Raft protobuf")));
}

#[test]
fn unknown_fields_and_noncanonical_values_are_preserved_without_reencoding() {
    let mut request = envelope();
    request.payload.extend_from_slice(&[
        0xa0, 0x06, 0x81, 0x00, // unknown 100, noncanonical varint 1
        0xa9, 0x06, 0, 1, 2, 3, 4, 5, 6, 7, // unknown 101, fixed64
        0xb5, 0x06, 8, 9, 10, 11, // unknown 102, fixed32
        0xba, 0x06, 0x81, 0x00, 0x42, // unknown 103, noncanonical length 1
        0xc0, 0x06, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1,
    ]);
    let original = request.payload.clone();
    let accepted = authorize(request).unwrap();
    assert_eq!(accepted.envelope().payload, original);
    assert_ne!(accepted.message().write_to_bytes().unwrap(), original);
}

#[test]
fn malformed_framing_unknown_enums_and_oversized_nested_lists_fail_before_parse() {
    let malformed = [
        vec![0xff],
        vec![0x20, 0x80],
        vec![0, 0],
        vec![0x80, 0x80, 0x80, 0x80, 0x10, 0],
        vec![0x0b],
        vec![0x0c],
        vec![0x0e],
        vec![0x0f],
        vec![0x80; 10],
        vec![
            0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2,
        ],
        vec![0xa1, 6, 0],
        vec![0xad, 6, 0],
        vec![0xb2, 6, 2, 0],
        vec![0x3a],
        vec![
            0xb2, 6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1,
        ],
    ];
    for payload in malformed {
        let mut request = envelope();
        request.payload = payload;
        assert!(matches!(authorize(request), Err(Error::Malformed(_))));
    }
    let mut unknown_kind = envelope();
    unknown_kind.payload.extend_from_slice(&[0x08, 0x13]);
    assert_eq!(
        authorize(unknown_kind),
        Err(Error::Unsupported("Raft message enum"))
    );
    let mut unknown_entry = envelope();
    unknown_entry.payload.extend_from_slice(&[0x3a, 2, 0x08, 3]);
    assert_eq!(
        authorize(unknown_entry),
        Err(Error::Unsupported("Raft entry enum"))
    );
    let mut snapshot = Snapshot::default();
    snapshot
        .mut_metadata()
        .mut_conf_state()
        .set_voters((1..=30).collect());
    let mut inner = message(MessageType::MsgSnapshot);
    inner.set_snapshot(snapshot);
    let mut p = policy();
    p.limits.max_fields = 10;
    assert_eq!(
        p.authorize(certificate(), 150, wrap(&inner)),
        Err(Error::Limit("Raft fields"))
    );
}

#[test]
fn append_and_snapshot_structures_are_bounded_while_application_bytes_stay_opaque() {
    let mut inner = message(MessageType::MsgAppend);
    for kind in [
        EntryType::EntryNormal,
        EntryType::EntryConfChange,
        EntryType::EntryConfChangeV2,
    ] {
        let mut entry = Entry::default();
        entry.set_entry_type(kind);
        entry.data = vec![0xff, 0xff].into();
        entry.context = vec![0xff].into();
        entry.index = 3;
        inner.mut_entries().push(entry);
    }
    assert_eq!(
        authorize(wrap(&inner)),
        Err(Error::Unsupported("Raft membership changes"))
    );
    inner.mut_entries().truncate(1);
    assert_eq!(authorize(wrap(&inner)).unwrap().message(), &inner);
    let mut snapshot = Snapshot {
        data: vec![0xff].into(),
        ..Default::default()
    };
    let metadata = snapshot.mut_metadata();
    metadata.index = 3;
    metadata.term = 2;
    let conf = metadata.mut_conf_state();
    conf.set_voters(vec![1, 2, 3]);
    inner = message(MessageType::MsgSnapshot);
    inner.set_snapshot(snapshot);
    assert_eq!(authorize(wrap(&inner)).unwrap().message(), &inner);
    // The initial service has fixed voters. Reject every form of config drift
    // before an authenticated peer can hand the snapshot to RawNode.
    for field in 0..7 {
        let mut invalid = inner.clone();
        let conf = invalid.mut_snapshot().mut_metadata().mut_conf_state();
        match field {
            0 => conf.set_voters(vec![1, 2, 3, 3]),
            1 => conf.set_voters(vec![1, 2, 4]),
            2 => conf.set_learners(vec![4]),
            3 => conf.set_voters_outgoing(vec![1, 2, 5]),
            4 => conf.set_learners_next(vec![5]),
            5 => conf.auto_leave = true,
            _ => conf.set_voters(vec![1, 1, 2]),
        }
        assert_eq!(
            authorize(wrap(&invalid)),
            Err(Error::Unsupported("snapshot bootstrap membership"))
        );
    }
}

#[test]
fn packed_configuration_members_share_the_nested_field_budget() {
    fn delimited(field: u8, value: &[u8]) -> Vec<u8> {
        let mut result = vec![(field << 3) | 2, value.len() as u8];
        result.extend_from_slice(value);
        result
    }
    fn request(configuration: &[u8]) -> Envelope {
        let mut metadata = delimited(1, configuration);
        metadata.extend_from_slice(&[0x10, 3, 0x18, 2]); // index 3, term 2
        let snapshot = delimited(2, &metadata);
        let mut request = wrap(&message(MessageType::MsgSnapshot));
        request.payload.extend_from_slice(&delimited(9, &snapshot));
        request
    }
    // Pinned generated code emits unpacked repeated uint64, but peers may
    // legally send the packed proto3 representation. Empty packed vectors are
    // likewise valid and must not consume a fabricated member allocation.
    let valid = request(&[0x0a, 3, 1, 2, 3, 0x12, 0, 0x1a, 0, 0x22, 0]);
    let accepted = authorize(valid.clone()).unwrap();
    assert_eq!(
        accepted
            .message()
            .get_snapshot()
            .get_metadata()
            .get_conf_state()
            .voters,
        vec![1, 2, 3]
    );
    let mut p = policy();
    p.limits.max_fields = 8;
    assert_eq!(
        p.authorize(certificate(), 150, valid),
        Err(Error::Limit("Raft fields"))
    );
    assert_eq!(
        authorize(request(&[0x0a, 1, 0x80])),
        Err(Error::Malformed("Raft truncated varint"))
    );
}

#[test]
fn certificate_parser_checks_complete_der_and_records_independent_fixture_values() {
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(include_bytes!("../fixtures/leaf.pem")).unwrap();
    let identity = certificate_identity(&pem.contents, pem.contents.len()).unwrap();
    assert_eq!(
        identity.fingerprint.as_slice(),
        hexadecimal("3bdeef20da77563d99f76ffdff6abeba7dd701ef7f870f4437256929627090dd")
    );
    assert_eq!(identity.not_before, 1_793_518_705);
    assert_eq!(identity.not_after, 2_108_878_705);
    assert_eq!(
        certificate_identity(&[], 4096),
        Err(Error::Limit("certificate DER"))
    );
    assert_eq!(
        certificate_identity(&pem.contents, pem.contents.len() - 1),
        Err(Error::Limit("certificate DER"))
    );
    assert_eq!(
        certificate_identity(&[0xff], 4096),
        Err(Error::Malformed("certificate DER"))
    );
    let mut trailing = pem.contents.clone();
    trailing.push(0);
    assert_eq!(
        certificate_identity(&trailing, 4096),
        Err(Error::Malformed("certificate DER trailing bytes"))
    );
    let mut reversed = pem.contents;
    let position = reversed
        .windows(13)
        .position(|part| part == b"361029073825Z")
        .unwrap();
    reversed[position..position + 13].copy_from_slice(b"251029073825Z");
    assert_eq!(
        certificate_identity(&reversed, 4096),
        Err(Error::Malformed("certificate validity interval"))
    );
    assert_eq!(Error::Unauthorized.to_string(), "Unauthorized");
}
