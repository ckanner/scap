//! Bounded transparent TCP fault fixture. TLS remains end-to-end: this fixture
//! never decrypts, parses, authenticates or delivers a Raft message itself.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Open,
    Blackhole,
    Refuse,
}

pub struct Proxy {
    pub address: SocketAddr,
    mode: watch::Sender<Mode>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
    accepted: Arc<AtomicU64>,
    transferred: Arc<AtomicU64>,
    destination: Arc<Mutex<SocketAddr>>,
}

impl Proxy {
    pub async fn start(destination: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (mode, mode_rx) = watch::channel(Mode::Open);
        let (stop, mut stop_rx) = watch::channel(false);
        let accepted = Arc::new(AtomicU64::new(0));
        let transferred = Arc::new(AtomicU64::new(0));
        let destination = Arc::new(Mutex::new(destination));
        let destination_task = Arc::clone(&destination);
        let accepted_task = Arc::clone(&accepted);
        let transferred_task = Arc::clone(&transferred);
        let task = tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(64));
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    ready = connections.join_next(), if !connections.is_empty() => {
                        ready.unwrap().expect("fixture proxy task panicked");
                    }
                    incoming = listener.accept() => {
                        let (socket, _) = incoming.unwrap();
                        // Do not add a Nagle/delayed-ACK transport model to a
                        // fixture whose fault modes are explicit below.
                        socket.set_nodelay(true).unwrap();
                        accepted_task.fetch_add(1, Ordering::Relaxed);
                        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                            drop(socket);
                            continue;
                        };
                        let rx = mode_rx.clone();
                        let count = Arc::clone(&transferred_task);
                        let destination = *destination_task.lock().unwrap();
                        connections.spawn(async move {
                            let _permit = permit;
                            relay(socket, destination, rx, count).await;
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Self {
            address,
            mode,
            stop,
            task,
            accepted,
            transferred,
            destination,
        }
    }

    pub fn set(&self, mode: Mode) {
        self.mode.send(mode).unwrap();
    }

    pub fn counters(&self) -> (u64, u64) {
        (
            self.accepted.load(Ordering::Relaxed),
            self.transferred.load(Ordering::Relaxed),
        )
    }

    pub fn retarget(&self, destination: SocketAddr) {
        *self.destination.lock().unwrap() = destination;
        let mode = *self.mode.borrow();
        self.mode.send(mode).unwrap();
    }

    pub async fn stop(self) {
        let _ = self.stop.send(true);
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("proxy shutdown deadline")
            .expect("proxy listener task failed");
    }
}

async fn relay(
    mut incoming: TcpStream,
    destination: SocketAddr,
    mut mode: watch::Receiver<Mode>,
    transferred: Arc<AtomicU64>,
) {
    let current = *mode.borrow_and_update();
    match current {
        Mode::Refuse => return,
        Mode::Blackhole => {
            // Accept TCP but do not forward TLS bytes. Hold the real socket
            // until the fixture heals or tears down; client deadlines are real.
            while *mode.borrow_and_update() == Mode::Blackhole {
                if mode.changed().await.is_err() {
                    return;
                }
            }
            return;
        }
        Mode::Open => {}
    }
    let Ok(Ok(mut outgoing)) =
        tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(destination)).await
    else {
        return;
    };
    outgoing.set_nodelay(true).unwrap();
    tokio::select! {
        copied = copy_bidirectional(&mut incoming, &mut outgoing) => {
            if let Ok((a, b)) = copied {
                transferred.fetch_add(a + b, Ordering::Relaxed);
            }
        }
        _ = mode.changed() => {
            while *mode.borrow_and_update() == Mode::Blackhole {
                if mode.changed().await.is_err() {
                    return;
                }
            }
        }
    }
}
