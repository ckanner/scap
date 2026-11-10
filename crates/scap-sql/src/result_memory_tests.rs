use super::*;
use crate::{StatementResult, Value};

fn root_bytes() -> u64 {
    size_of::<TransactionResult>() as u64
}

fn allocation_error() -> TryReserveError {
    Vec::<u8>::new().try_reserve_exact(usize::MAX).unwrap_err()
}

#[test]
fn root_empty_values_and_zsts_are_bounded_without_allocating() {
    for limit in [0, root_bytes() - 1] {
        assert!(matches!(
            ResultMemoryBudget::new(limit),
            Err(SqlError::ResourceExhausted)
        ));
    }
    let mut memory = ResultMemoryBudget::new(root_bytes()).unwrap();
    assert_eq!(memory.text("").unwrap(), "");
    assert!(memory.blob(&[]).unwrap().is_empty());
    let mut values = Vec::<()>::new();
    memory.reserve(&mut values, usize::MAX).unwrap();
    values.push(());
    assert_eq!(memory.used, root_bytes());
    assert_eq!(
        memory.reserve(&mut values, usize::MAX),
        Err(SqlError::ResourceExhausted)
    );
    assert_eq!(values.len(), 1);
}

#[test]
fn nested_graph_charges_container_capacity_columns_and_payloads() {
    let mut memory = ResultMemoryBudget::new(4096).unwrap();
    let mut statements = Vec::new();
    memory.reserve(&mut statements, 2).unwrap();
    let mut columns = Vec::new();
    memory.reserve(&mut columns, 3).unwrap();
    columns.push(memory.text("中文").unwrap());
    columns.push(memory.text("b").unwrap());
    columns.push(memory.text("n").unwrap());
    let mut rows = Vec::new();
    memory.reserve(&mut rows, 2).unwrap();
    let mut values = Vec::new();
    memory.reserve(&mut values, 3).unwrap();
    values.push(Value::Text(memory.text("text").unwrap()));
    values.push(Value::Blob(memory.blob(&[0, 255, 4]).unwrap()));
    values.push(Value::Null);
    rows.push(values);
    statements.push(StatementResult {
        columns,
        rows,
        affected_rows: 0,
        last_insert_rowid: 0,
    });
    let expected = root_bytes()
        + (2 * size_of::<StatementResult>()) as u64
        + (3 * size_of::<String>()) as u64
        + (2 * size_of::<Vec<Value>>()) as u64
        + (3 * size_of::<Value>()) as u64
        + 6
        + 1
        + 1
        + 4
        + 3;
    assert_eq!(memory.used, expected);
    assert_eq!(statements[0].columns[0], "中文");
    assert_eq!(statements[0].rows[0][2], Value::Null);
    // All previously allocated capacity is retained in the charge, even when
    // the logical length is smaller than its capacity.
    assert_eq!(statements.len(), 1);
    assert_eq!(statements.capacity(), 2);
}

#[test]
fn replacing_capacity_requires_old_and_new_buffers_to_fit_together() {
    let slot = size_of::<u64>() as u64;
    let mut memory = ResultMemoryBudget::new(root_bytes() + 2 * slot).unwrap();
    let mut values = Vec::new();
    memory.reserve(&mut values, 1).unwrap();
    values.push(7_u64);
    let before = memory.used;
    assert_eq!(
        memory.reserve(&mut values, 1),
        Err(SqlError::ResourceExhausted),
        "the final two slots fit, but both old and replacement buffers do not"
    );
    assert_eq!(memory.used, before);
    assert_eq!(values, [7]);
    memory.maximum = root_bytes() + 3 * slot;
    memory.reserve(&mut values, 1).unwrap();
    values.push(8);
    assert_eq!(values, [7, 8]);
    assert_eq!(memory.used, root_bytes() + 2 * slot);
    memory.reserve(&mut values, 0).unwrap();
    assert_eq!(memory.used, root_bytes() + 2 * slot);
}

#[test]
fn refusal_precedes_allocation_and_fallible_allocation_preserves_the_old_graph() {
    let mut memory = ResultMemoryBudget::new(root_bytes()).unwrap();
    let mut values = Vec::<u8>::new();
    assert_eq!(
        memory.reserve_with(&mut values, 1, |_, _| panic!("must not allocate")),
        Err(SqlError::ResourceExhausted)
    );
    memory.maximum += 1;
    assert_eq!(
        memory.reserve_with(&mut values, 1, |_, _| Err(allocation_error())),
        Err(SqlError::ResourceExhausted)
    );
    assert_eq!(memory.used, root_bytes());
    assert_eq!(values.capacity(), 0);
    memory.reserve(&mut values, 1).unwrap();
    values.push(5);
    memory.maximum += 2;
    assert_eq!(
        memory.reserve_with(&mut values, 1, |_, _| Err(allocation_error())),
        Err(SqlError::ResourceExhausted)
    );
    assert_eq!(values, [5]);
    assert_eq!(memory.used, root_bytes() + 1);
    // A real capacity-overflow failure is deterministic and does not request
    // an enormous allocation from the operating system.
    let mut memory = ResultMemoryBudget::new(u64::MAX).unwrap();
    assert_eq!(
        memory.reserve(&mut Vec::<u8>::new(), isize::MAX as usize + 1),
        Err(SqlError::ResourceExhausted)
    );
    assert_eq!(memory.used, root_bytes());
}

#[test]
fn allocator_reported_capacity_is_reconciled_before_accepting_a_replacement() {
    let mut memory = ResultMemoryBudget::new(root_bytes() + 2).unwrap();
    let mut values = Vec::<u8>::new();
    memory
        .reserve_with(&mut values, 1, |replacement, requested| {
            replacement.try_reserve_exact(requested + 1).unwrap();
            Ok(())
        })
        .unwrap();
    assert_eq!(values.capacity(), 2);
    assert_eq!(memory.used, root_bytes() + 2);
    let mut memory = ResultMemoryBudget::new(root_bytes() + 1).unwrap();
    let mut values = Vec::<u8>::new();
    assert_eq!(
        memory.reserve_with(&mut values, 1, |replacement, requested| {
            replacement.try_reserve_exact(requested + 1).unwrap();
            Ok(())
        }),
        Err(SqlError::ResourceExhausted)
    );
    assert_eq!(values.capacity(), 0);
    assert_eq!(memory.used, root_bytes());
}

#[test]
fn arithmetic_and_invalid_untracked_capacity_fail_closed() {
    assert_eq!(
        growth_capacity(usize::MAX, 1),
        Err(SqlError::ResourceExhausted)
    );
    let mut memory = ResultMemoryBudget::new(u64::MAX).unwrap();
    memory.used = u64::MAX;
    assert_eq!(memory.check_additional(1), Err(SqlError::ResourceExhausted));
    let mut memory = ResultMemoryBudget::new(4096).unwrap();
    let mut untracked = vec![0_u8; 128];
    assert_eq!(
        memory.reserve(&mut untracked, 1),
        Err(SqlError::ResourceExhausted)
    );
    assert_eq!(untracked, vec![0_u8; 128]);
    assert_eq!(memory.used, root_bytes());
    assert_eq!(allocation_bytes::<()>(usize::MAX), Ok(0));
}

#[test]
fn nonzero_sized_slots_keep_the_original_graph_across_all_reservation_failures() {
    let slot = size_of::<u64>() as u64;
    let mut memory = ResultMemoryBudget::new(root_bytes() + 3 * slot).unwrap();
    let mut values = Vec::<u64>::new();
    memory.reserve(&mut values, 1).unwrap();
    values.push(7);
    assert_eq!(
        memory.reserve(&mut values, usize::MAX),
        Err(SqlError::ResourceExhausted),
        "a non-ZST length addition must fail before any allocation"
    );
    assert_eq!(
        memory.reserve_with(&mut values, 1, |_, _| Err(allocation_error())),
        Err(SqlError::ResourceExhausted)
    );
    assert_eq!(
        memory.reserve_with(&mut values, 1, |replacement, requested| {
            replacement.try_reserve_exact(requested + 1)
        }),
        Err(SqlError::ResourceExhausted),
        "reported capacity must still fit alongside the old allocation"
    );
    assert_eq!(values, [7]);
    assert_eq!(values.capacity(), 1);
    assert_eq!(memory.used, root_bytes() + slot);
    memory.maximum += slot;
    memory
        .reserve_with(&mut values, 1, |replacement, requested| {
            replacement.try_reserve_exact(requested + 1)
        })
        .unwrap();
    assert_eq!(values, [7]);
    assert_eq!(values.capacity(), 3);
    assert_eq!(memory.used, root_bytes() + 3 * slot);

    let mut memory = ResultMemoryBudget::new(u64::MAX).unwrap();
    let mut untracked = vec![0_u64; 128];
    assert_eq!(
        memory.reserve(&mut untracked, 1),
        Err(SqlError::ResourceExhausted)
    );
    assert_eq!(
        memory.reserve(
            &mut Vec::<u64>::new(),
            isize::MAX as usize / size_of::<u64>() + 1
        ),
        Err(SqlError::ResourceExhausted),
        "a byte count above isize::MAX fails in Vec without requesting OS memory"
    );
    assert_eq!(memory.used, root_bytes());
}

#[cfg(target_pointer_width = "64")]
#[test]
fn byte_size_multiplication_overflow_never_reaches_the_allocator() {
    assert_eq!(
        allocation_bytes::<u64>(usize::MAX),
        Err(SqlError::ResourceExhausted)
    );
    let mut memory = ResultMemoryBudget::new(u64::MAX).unwrap();
    assert_eq!(
        memory.reserve_with(&mut Vec::<u64>::new(), usize::MAX, |_, _| {
            panic!("must reject multiplication before allocating")
        }),
        Err(SqlError::ResourceExhausted)
    );
}

#[test]
fn text_and_blob_refusals_keep_resource_errors_and_separate_wire_bytes() {
    for text in [false, true] {
        let mut memory = ResultMemoryBudget::new(root_bytes() + 3).unwrap();
        let result = if text {
            memory.text("four").map(|_| ())
        } else {
            memory.blob(b"four").map(|_| ())
        };
        assert_eq!(result, Err(SqlError::ResourceExhausted));
        assert_eq!(memory.used, root_bytes());
    }
    let mut memory = ResultMemoryBudget::new(root_bytes() + 1).unwrap();
    assert_eq!(
        memory.reserve(&mut Vec::<Value>::new(), 1),
        Err(SqlError::ResourceExhausted),
        "one encoded NULL byte cannot pay for its Value slot"
    );
}
