use super::*;
use libsql_sys::rusqlite::types::ToSqlOutput;

#[test]
fn parameter_adapter_borrows_the_original_text_and_blob_buffers() {
    let text = "SQLite\0中文".repeat(512);
    let blob: Vec<_> = (0..4096).map(|index| (index % 256) as u8).collect();
    let text_value = Value::Text(text);
    let blob_value = Value::Blob(blob);

    let Value::Text(original) = &text_value else {
        unreachable!();
    };
    let ToSqlOutput::Borrowed(ValueRef::Text(borrowed)) = sql::native_value(&text_value) else {
        panic!("text parameters must borrow the original request");
    };
    assert_eq!(borrowed.as_ptr(), original.as_ptr());
    assert_eq!(borrowed, original.as_bytes());

    let Value::Blob(original) = &blob_value else {
        unreachable!();
    };
    let ToSqlOutput::Borrowed(ValueRef::Blob(borrowed)) = sql::native_value(&blob_value) else {
        panic!("blob parameters must borrow the original request");
    };
    assert_eq!(borrowed.as_ptr(), original.as_ptr());
    assert_eq!(borrowed, original);
}

#[test]
fn native_parameter_bindings_own_the_values_before_the_request_is_changed() {
    let connection = libsql_sys::rusqlite::Connection::open_in_memory().unwrap();
    let mut prepared = connection.prepare("SELECT ?1,?2,?3,?4,?5,?6,?7").unwrap();
    let mut parameters = vec![
        Value::Null,
        Value::Integer(i64::MIN),
        Value::Real(1.25),
        Value::Text("bound\0中文".into()),
        Value::Blob(vec![0, 255, 1, 128]),
        Value::Text(String::new()),
        Value::Blob(Vec::new()),
    ];
    for (index, value) in parameters.iter().enumerate() {
        prepared
            .raw_bind_parameter(index + 1, sql::native_value(value))
            .unwrap();
    }

    // Overwrite the same source allocations before freeing them. If the safe
    // binder ever changes to SQLITE_STATIC these exact-value checks must fail.
    if let Value::Text(text) = &mut parameters[3] {
        text.replace_range(.., "changed");
    }
    if let Value::Blob(blob) = &mut parameters[4] {
        blob.fill(42);
    }
    drop(parameters);

    let mut rows = prepared.raw_query();
    let row = rows.next().unwrap().unwrap();
    assert_eq!(row.get_ref(0).unwrap(), ValueRef::Null);
    assert_eq!(row.get::<_, i64>(1).unwrap(), i64::MIN);
    assert_eq!(row.get::<_, f64>(2).unwrap(), 1.25);
    assert_eq!(row.get::<_, String>(3).unwrap(), "bound\0中文");
    assert_eq!(row.get::<_, Vec<u8>>(4).unwrap(), [0, 255, 1, 128]);
    assert_eq!(row.get_ref(5).unwrap(), ValueRef::Text(b""));
    assert_eq!(row.get_ref(6).unwrap(), ValueRef::Blob(b""));
    assert!(rows.next().unwrap().is_none());
}

#[test]
fn bound_payloads_survive_request_drop_and_private_image_recovery() {
    let (root, mut writer, plan) = setup();
    writer
        .execute(
            &[statement("CREATE TABLE payloads(t TEXT, b BLOB)")],
            uninterrupted(),
        )
        .unwrap();
    let expected = vec![
        Value::Text("persisted\0中文".repeat(64)),
        Value::Blob((0..4096).map(|index| (index % 256) as u8).collect()),
    ];
    let request = Statement {
        sql: "INSERT INTO payloads VALUES(?1,?2) RETURNING t,b".into(),
        parameters: expected.clone(),
    };
    let result = writer
        .execute(std::slice::from_ref(&request), uninterrupted())
        .unwrap();
    drop(request);
    assert_eq!(result.statements[0].rows, vec![expected.clone()]);
    assert_eq!(
        scap_sql::decode_result(&plan.borrow().writes[1].1, limits().sql).unwrap(),
        result
    );
    let recovered = captured_image(&plan.borrow());
    drop(writer);
    let mut second = create_writer(
        &root.path().join("recovered"),
        recovered,
        limits(),
        Gate(plan),
    )
    .unwrap();
    let read = second
        .query(&[statement("SELECT t,b FROM payloads")], uninterrupted())
        .unwrap();
    assert_eq!(read.statements[0].rows, vec![expected]);
}
