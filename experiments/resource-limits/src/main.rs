//! Explicit experiment assembly: production HTTP/scheduler/native engine/S3,
//! with one operator-controlled pause before an exact HEAD GET. No database
//! protocol is implemented here and this binary is not a production daemon.

use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use scap_object_store::{Condition, Objects, StoreError, Stored, S3};
use scap_service::auth::Principal;
use scap_service::config::Config;
use scap_service::engine::Engine;
use scap_service::scheduler::{Factory, Scheduler, Worker};
use scap_service::wire::{Action, Call};
use scap_service::{daemon, http, Failure};
use serde::Deserialize;
use serde_json::{json, Value};

static EVENTS: Mutex<u64> = Mutex::new(0);
static START: OnceLock<Instant> = OnceLock::new();

fn emit(event: &str, fields: Value) {
    let mut sequence = EVENTS.lock().expect("event lock");
    *sequence += 1;
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(
        &mut output,
        &json!({
            "schema": 1, "sequence": *sequence, "event": event,
            "elapsed_ns": START.get_or_init(Instant::now).elapsed().as_nanos(),
            "fields": fields
        }),
    )
    .expect("event serialization");
    writeln!(output).expect("event write");
    output.flush().expect("event flush");
}

#[derive(Default)]
struct Pause {
    key: Option<String>,
    entered: bool,
    released: bool,
}

#[derive(Default)]
struct Gate {
    state: Mutex<Pause>,
    wake: Condvar,
}

struct PausingObjects {
    inner: Arc<S3>,
    gate: Arc<Gate>,
}

impl Objects for PausingObjects {
    fn get(&self, key: &str, max_bytes: usize, deadline: Instant) -> Result<Stored, StoreError> {
        let mut pause = self.gate.state.lock().expect("pause lock");
        let paused = pause.key.as_deref() == Some(key) && !pause.entered;
        if paused {
            pause.entered = true;
            emit(
                "head_pause_entered",
                json!({"key": key, "max_bytes": max_bytes,
                "deadline_remaining_ns": deadline.saturating_duration_since(Instant::now()).as_nanos()}),
            );
            let until = Instant::now() + Duration::from_secs(20);
            while !pause.released {
                let (next, waited) = self
                    .gate
                    .wake
                    .wait_timeout(pause, until.saturating_duration_since(Instant::now()))
                    .expect("pause wait");
                pause = next;
                if waited.timed_out() {
                    emit("head_pause_expired", json!({"key": key}));
                    return Err(StoreError::Unknown);
                }
            }
        }
        drop(pause);
        // The caller's original deadline is passed unchanged, even when it
        // elapsed during the deliberate worker pause. No response is invented.
        let result = self.inner.get(key, max_bytes, deadline);
        if paused {
            emit(
                "head_pause_returned",
                json!({"key": key,
                "deadline_elapsed": Instant::now() >= deadline,
                "outcome": result.as_ref().map(|_| "ok").unwrap_or("error")}),
            );
        }
        result
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        deadline: Instant,
    ) -> Result<String, StoreError> {
        self.inner.put(key, bytes, condition, deadline)
    }
}

struct ObservedWorker {
    engine: Engine,
    calls: Arc<AtomicU64>,
}

impl ObservedWorker {
    fn observe(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
        output: Option<&mut scap_service::output::OutputContext>,
    ) -> Result<Value, Failure> {
        let serial = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let operation = match call.action {
            Action::Create { .. } => "create",
            Action::Activate { .. } => "activate",
            Action::Execute { .. } => "execute",
            Action::Query { .. } => "query",
            Action::Lookup { .. } => "lookup",
            Action::Cancel { .. } => "cancel",
            Action::Status { .. } => "status",
            _ => "other",
        };
        let fields = json!({"serial": serial, "operation": operation,
            "tenant": principal.tenant, "principal": principal.principal,
            "database": call.scope.database.0});
        emit("worker_entered", fields.clone());
        let result = match output {
            Some(output) => self
                .engine
                .execute_budgeted(principal, call, deadline, output),
            None => self.engine.execute(principal, call, deadline),
        };
        let mut fields = fields;
        fields["outcome"] = json!(match &result {
            Ok(_) => "ok",
            Err(error) => error.code,
        });
        emit("worker_completed", fields);
        result
    }
}

impl Worker for ObservedWorker {
    fn execute(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
    ) -> Result<Value, Failure> {
        self.observe(principal, call, deadline, None)
    }

    fn execute_budgeted(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
        output: &mut scap_service::output::OutputContext,
    ) -> Result<Value, Failure> {
        self.observe(principal, call, deadline, Some(output))
    }
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Arm { id: String, key: String },
    Release { id: String },
    Observe { id: String },
    Shutdown { id: String },
}

fn main() -> Result<(), String> {
    START.set(Instant::now()).expect("start once");
    let config = std::env::args()
        .nth(1)
        .ok_or("configuration path required")?;
    let prepared = Config::parse(&std::fs::read(config).map_err(|e| e.to_string())?)
        .and_then(Config::prepare)
        .map_err(|e| format!("configuration: {e:?}"))?;
    if prepared.service.catalogue.is_some() || prepared.service.discovery.is_some() {
        return Err("resource experiment enables only database API".into());
    }
    let owner = prepared.service.worker_instance;
    let options = prepared.service.options.clone();
    let cache = prepared.service.cache_directory.clone();
    let pages = prepared.service.cache.pages_per_actor;
    let recoveries = Arc::new(tokio::sync::Semaphore::new(
        prepared.service.cache.parallel_recoveries,
    ));
    let limits = prepared.service.admission.limits();
    let backend = Arc::new(S3::new(prepared.s3).map_err(|e| format!("S3: {e:?}"))?);
    let gate = Arc::new(Gate::default());
    let objects: Arc<dyn Objects> = Arc::new(PausingObjects {
        inner: backend,
        gate: gate.clone(),
    });
    let (address, mut state) = daemon::assemble(prepared.service, objects.clone())
        .map_err(|e| format!("assemble: {e:?}"))?;
    let calls = Arc::new(AtomicU64::new(0));
    let factory: Factory = Arc::new(move |_| {
        Ok(Box::new(ObservedWorker {
            engine: Engine::new(
                objects.clone(),
                owner,
                options.clone(),
                &cache,
                1,
                pages,
                recoveries.clone(),
            )?,
            calls: calls.clone(),
        }))
    });
    // The factory adds observation around the same public production Engine.
    // The production assembly still validates/configures all HTTP intake pools.
    Arc::get_mut(&mut state)
        .ok_or("unexpected shared state")?
        .scheduler =
        Arc::new(Scheduler::new(limits, factory).map_err(|e| format!("scheduler: {e:?}"))?);
    let router = http::router(state.clone()).map_err(|e| format!("router: {e:?}"))?;
    let listener = std::net::TcpListener::bind(address).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let address = listener.local_addr().map_err(|e| e.to_string())?;
    let (send, receive) = tokio::sync::oneshot::channel();
    let observer = state.clone();
    let control = std::thread::spawn(move || {
        let mut send = Some(send);
        for line in std::io::stdin().lock().lines() {
            let line = line.expect("operator input");
            assert!(line.len() <= 4096, "bounded operator input");
            let command: Command = serde_json::from_str(&line).expect("operator command");
            match command {
                Command::Arm { id, key } => {
                    assert!(key.ends_with("/head"));
                    let mut pause = gate.state.lock().expect("pause lock");
                    assert!(pause.key.is_none(), "one pause only");
                    pause.key = Some(key.clone());
                    emit("pause_armed", json!({"id": id, "key": key}));
                }
                Command::Release { id } => {
                    let mut pause = gate.state.lock().expect("pause lock");
                    assert!(
                        pause.entered && !pause.released,
                        "release entered pause once"
                    );
                    pause.released = true;
                    emit("pause_released", json!({"id": id, "key": pause.key}));
                    gate.wake.notify_all();
                }
                Command::Observe { id } => emit(
                    "admission_observed",
                    json!({"id": id,
                    "data_available": observer.intake.available_permits(),
                    "control_available": observer.control_intake.available_permits(),
                    "recovery_available": observer.recovery_intake.available_permits()}),
                ),
                Command::Shutdown { id } => {
                    gate.state.lock().expect("pause lock").released = true;
                    gate.wake.notify_all();
                    emit("shutdown_requested", json!({"id": id}));
                    let _ = send.take().expect("shutdown once").send(());
                    break;
                }
            }
        }
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::from_std(listener).map_err(|e| e.to_string())?;
        emit("listening", json!({"address": address.to_string()}));
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = receive.await;
            })
            .await
            .map_err(|e| e.to_string())
    })?;
    control.join().map_err(|_| "operator thread failed")?;
    drop(runtime);
    drop(state);
    emit("worker_process_finished", json!({"status": "clean"}));
    Ok(())
}
