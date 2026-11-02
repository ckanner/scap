use super::*;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

struct Local {
    accepted: Arc<AtomicUsize>,
    peers: Arc<Mutex<Vec<DuplexStream>>>,
    address_error: bool,
    pending: bool,
}

impl Listener for Local {
    type Io = DuplexStream;
    type Addr = usize;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        if self.pending {
            std::future::pending::<()>().await;
        }
        let number = self.accepted.fetch_add(1, Ordering::Relaxed);
        let (io, peer) = tokio::io::duplex(32);
        self.peers.lock().push(peer);
        (io, number)
    }
    fn local_addr(&self) -> io::Result<Self::Addr> {
        if self.address_error {
            Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
        } else {
            Ok(42)
        }
    }
}

fn listener() -> Bounded<Local> {
    Bounded::new(Local {
        accepted: Arc::new(AtomicUsize::new(0)),
        peers: Arc::new(Mutex::new(Vec::new())),
        address_error: false,
        pending: false,
    })
}

#[tokio::test]
async fn connection_slot_is_reserved_before_accept_and_cancelled_waits_do_not_leak() {
    let mut listener = listener();
    assert_eq!(listener.lifetime, Duration::from_secs(30));
    assert_eq!(listener.local_addr().unwrap(), 42);
    listener.inner.address_error = true;
    assert_eq!(
        listener.local_addr().unwrap_err().kind(),
        io::ErrorKind::AddrNotAvailable
    );
    let accepted = listener.inner.accepted.clone();
    let slots = listener.slots.clone();
    listener.inner.pending = true;
    let mut pending_accept = Box::pin(listener.accept());
    let mut context = Context::from_waker(Waker::noop());
    assert!(pending_accept.as_mut().poll(&mut context).is_pending());
    assert_eq!(slots.available_permits(), 63);
    assert_eq!(accepted.load(Ordering::Relaxed), 0);
    drop(pending_accept);
    assert_eq!(slots.available_permits(), 64);
    listener.inner.pending = false;
    let mut held = Vec::new();
    for id in 0..64 {
        let (connection, address) = listener.accept().await;
        assert_eq!(address, id);
        held.push(connection);
    }
    assert_eq!(listener.slots.available_permits(), 0);
    let mut waiting = Box::pin(listener.accept());
    let mut context = Context::from_waker(Waker::noop());
    assert!(waiting.as_mut().poll(&mut context).is_pending());
    assert_eq!(accepted.load(Ordering::Relaxed), 64);
    drop(waiting);
    drop(held.pop());
    assert_eq!(listener.slots.available_permits(), 1);
    let (connection, address) = listener.accept().await;
    assert_eq!(address, 64);
    assert_eq!(listener.slots.available_permits(), 0);
    drop(connection);
    drop(held);
    assert_eq!(listener.slots.available_permits(), 64);
}

#[tokio::test]
async fn connection_forwards_reads_writes_flush_shutdown_eof_and_io_errors() {
    let mut listener = listener();
    let (mut connection, _) = listener.accept().await;
    let mut peer = listener.inner.peers.lock().pop().unwrap();
    peer.write_all(b"abc").await.unwrap();
    let mut bytes = [0; 3];
    connection.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"abc");
    connection.write_all(b"def").await.unwrap();
    connection.flush().await.unwrap();
    peer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"def");
    connection.shutdown().await.unwrap();
    assert_eq!(peer.read(&mut bytes).await.unwrap(), 0);
    drop(peer);
    assert_eq!(connection.read(&mut bytes).await.unwrap(), 0);
    assert_eq!(
        connection.write(b"x").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[tokio::test(start_paused = true)]
async fn absolute_lifetime_is_not_extended_by_progress_and_covers_every_io_method() {
    let mut listener = listener();
    let (mut connection, _) = listener.accept().await;
    let mut peer = listener.inner.peers.lock().pop().unwrap();
    tokio::time::advance(Duration::from_secs(29)).await;
    peer.write_all(b"x").await.unwrap();
    let mut byte = [0; 1];
    connection.read_exact(&mut byte).await.unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        connection.read(&mut byte).await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        connection.write(b"x").await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        connection.flush().await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        connection.shutdown().await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(listener.slots.available_permits(), 63);
    drop(connection);
    assert_eq!(listener.slots.available_permits(), 64);
}

#[tokio::test(start_paused = true)]
async fn pending_partial_request_is_woken_by_the_same_connection_deadline() {
    struct Notifications(AtomicUsize);
    impl Wake for Notifications {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let mut listener = listener();
    let (mut connection, _) = listener.accept().await;
    let mut byte = [0; 1];
    let mut read = Box::pin(connection.read(&mut byte));
    let notifications = Arc::new(Notifications(AtomicUsize::new(0)));
    let waker = Waker::from(notifications.clone());
    let mut context = Context::from_waker(&waker);
    assert!(read.as_mut().poll(&mut context).is_pending());
    tokio::time::advance(Duration::from_secs(31)).await;
    assert!(notifications.0.load(Ordering::Relaxed) > 0);
    assert_eq!(read.await.unwrap_err().kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn node_stop_wakes_pending_io_and_closes_every_connection_method() {
    for sender_closed in [false, true] {
        let (sender, signal) = watch::channel(false);
        let mut listener = Bounded::with_stop(listener().inner, signal);
        let (mut connection, _) = listener.accept().await;
        let mut byte = [0; 1];
        let mut read = Box::pin(connection.read(&mut byte));
        let mut context = Context::from_waker(Waker::noop());
        assert!(read.as_mut().poll(&mut context).is_pending());
        if sender_closed {
            drop(sender);
        } else {
            sender.send(true).unwrap();
        }
        assert_eq!(
            read.await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            connection.write(b"x").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            connection.flush().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            connection.shutdown().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        drop(connection);
        assert_eq!(listener.slots.available_permits(), 64);
    }
    let (_sender, receiver) = watch::channel(true);
    stopped(Some(receiver)).await;
}
