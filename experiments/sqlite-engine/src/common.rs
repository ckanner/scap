//! Shared fixed, synthetic fixture inputs; no service configuration.
use scap_cell::{CellIdentity, DatabaseIdentity};
use scap_engine::{EngineIdentity, Limits};
use scap_sql::{SqlLimits, Statement};
use scap_sqlite::WriterLimits;

pub const KILL_REQUEST: u128 = 1001;

pub fn engine_identity() -> EngineIdentity {
    EngineIdentity {
        cell: CellIdentity {
            cell_id: 0x53434150,
            cell_incarnation: 7,
        },
        database: DatabaseIdentity {
            database_id: 0x53514c495445,
            incarnation: 4,
            placement_generation: 1,
        },
    }
}

pub fn engine_limits() -> Limits {
    Limits {
        max_database_pages: 64,
        max_changed_pages: 64,
        max_transaction_bytes: 300 * 1024,
    }
}

pub fn writer_limits() -> WriterLimits {
    WriterLimits {
        sql: SqlLimits {
            max_statements: 16,
            max_sql_bytes: 16 * 1024,
            max_parameters: 32,
            max_columns: 16,
            max_rows: 64,
            max_result_bytes: 16 * 1024,
            max_value_bytes: 12 * 1024,
        },
        max_vm_steps: 200_000,
        max_changed_pages: 64,
    }
}

pub fn sql(text: &str) -> Statement {
    Statement {
        sql: text.into(),
        parameters: Vec::new(),
    }
}

pub fn kill_batch() -> Vec<Statement> {
    vec![
        sql("CREATE TABLE items(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)"),
        sql("INSERT INTO items VALUES(1, randomblob(32)) RETURNING payload"),
    ]
}
