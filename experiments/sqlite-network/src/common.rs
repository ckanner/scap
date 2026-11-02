//! Bounded synthetic limits shared by real SQL/network fault fixtures.
use std::time::Duration;

use raft::{Config, ReadOnlyOption};
use scap_cell::{Admission, CellIdentity, DatabaseIdentity, Position};
use scap_raft_driver::DriverConfig;
use scap_raft_store::Identity;
use scap_raft_transport::TransportLimits;
use scap_raft_wire::{Binding, Policy, Scope};

pub const CLUSTER: u128 = 0x53434150;
pub const CELL: u128 = 0x4e4554574f524b;
pub const CELL_GENERATION: u64 = 7;
pub const ADMINISTRATOR: u128 = 101;
pub const READER: u128 = 102;
pub const DATABASE: DatabaseIdentity = DatabaseIdentity {
    database_id: 0x44415441,
    incarnation: 2,
    placement_generation: 1,
};
pub fn cell() -> CellIdentity {
    CellIdentity {
        cell_id: CELL,
        cell_incarnation: CELL_GENERATION,
    }
}

pub fn identity(node_id: u64) -> Identity {
    Identity {
        cluster_id: CLUSTER,
        cell_id: CELL,
        cell_incarnation: CELL_GENERATION,
        node_id,
    }
}

pub fn genesis() -> Position {
    Position { term: 1, index: 1 }
}

pub fn cell_limits() -> scap_cell::Limits {
    scap_cell::Limits {
        max_state_bytes: 2 * 1024 * 1024,
        max_command_bytes: 400 * 1024,
        max_databases: 8,
        max_policy_grants: 8,
        max_admin_operations: 64,
        max_requests_per_database: 128,
        max_transaction_bytes: 300 * 1024,
        max_result_bytes: 16 * 1024,
    }
}

pub fn store_limits() -> scap_raft_store::Limits {
    scap_raft_store::Limits {
        max_image_bytes: 16 * 1024 * 1024,
        max_entry_bytes: 500 * 1024,
        max_entries: 512,
        max_application_bytes: 2 * 1024 * 1024,
    }
}

pub fn driver_config(node: u64, boot_id: u128) -> DriverConfig {
    // Distinct finite election windows reduce fixture races. These are test
    // parameters, not production election or RTO recommendations.
    let election = 20 + usize::try_from(node).unwrap() * 10;
    DriverConfig {
        raft: Config {
            election_tick: 20,
            heartbeat_tick: 2,
            min_election_tick: election,
            max_election_tick: election + 1,
            max_size_per_msg: 512 * 1024,
            max_inflight_msgs: 16,
            max_uncommitted_size: 4 * 1024 * 1024,
            max_committed_size_per_ready: 1024 * 1024,
            pre_vote: true,
            check_quorum: true,
            read_only_option: ReadOnlyOption::Safe,
            ..Config::default()
        },
        boot_id,
        max_input_bytes: 3 * 1024 * 1024,
        max_output_messages: 64,
        max_output_bytes: 8 * 1024 * 1024,
        max_pending_reads: 16,
        max_pending_proposals: 16,
        max_pending_proposal_bytes: 2 * 1024 * 1024,
        max_ready_rounds: 32,
    }
}

pub fn transport_limits() -> TransportLimits {
    TransportLimits {
        max_wire_bytes: 4 * 1024 * 1024,
        max_connections: 32,
        max_inflight_requests: 16,
        max_streams_per_connection: 4,
        max_header_bytes: 8192,
        handshake_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        connect_timeout: Duration::from_secs(2),
        max_connection_age: Duration::from_secs(30),
        connection_grace: Duration::from_secs(2),
    }
}

pub fn policy(node_id: u64, bindings: Vec<Binding>) -> Policy {
    Policy::new(
        Scope {
            cluster_id: CLUSTER,
            cell_id: CELL,
            cell_incarnation: CELL_GENERATION,
            node_id,
        },
        vec![1, 2, 3],
        bindings,
        scap_raft_wire::Limits {
            max_payload_bytes: 3 * 1024 * 1024,
            max_entries: 512,
            max_fields: 16 * 1024,
            max_certificate_bytes: 16 * 1024,
            max_bindings: 16,
        },
    )
    .unwrap()
}

pub fn admission() -> Admission {
    Admission {
        principal_id: ADMINISTRATOR,
        credential_id: 202,
        admission_id: 303,
        auth_epoch: 1,
    }
}

pub fn engine_identity() -> scap_engine::EngineIdentity {
    scap_engine::EngineIdentity {
        cell: cell(),
        database: DATABASE,
    }
}

pub fn engine_limits() -> scap_engine::Limits {
    scap_engine::Limits {
        max_database_pages: 64,
        max_changed_pages: 64,
        max_transaction_bytes: 300 * 1024,
    }
}

pub fn writer_limits() -> scap_sqlite::WriterLimits {
    scap_sqlite::WriterLimits {
        sql: scap_sql::SqlLimits {
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

pub fn sql(text: &str) -> scap_sql::Statement {
    scap_sql::Statement {
        sql: text.into(),
        parameters: Vec::new(),
    }
}
