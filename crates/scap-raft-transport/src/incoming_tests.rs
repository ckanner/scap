use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;

#[tokio::test]
async fn connection_permits_cover_io_lifetime_and_preserve_read_write_operations() {
    let semaphore = Arc::new(Semaphore::new(1));
    let (first, mut peer) = tokio::io::duplex(64);
    let (second, _other) = tokio::io::duplex(64);
    let mut incoming = BoundedIncoming::new(
        tokio_stream::iter([Ok(first), Ok(second)]),
        Arc::clone(&semaphore),
    );
    let mut bounded = incoming.next().await.unwrap().unwrap();
    assert_eq!(semaphore.available_permits(), 0);
    std::future::poll_fn(|cx| {
        assert!(Pin::new(&mut incoming).poll_next(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    bounded.connect_info();
    bounded.write_all(b"ping").await.unwrap();
    bounded.flush().await.unwrap();
    let mut request = [0; 4];
    peer.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"ping");
    peer.write_all(b"pong").await.unwrap();
    bounded.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"pong");
    bounded.shutdown().await.unwrap();
    drop(bounded);
    drop(incoming.next().await.unwrap().unwrap());
    assert!(incoming.next().await.is_none());
    assert_eq!(semaphore.available_permits(), 1);
}

#[tokio::test]
async fn listener_pending_error_exhaustion_and_closed_budget_release_slots() {
    let semaphore = Arc::new(Semaphore::new(1));
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let mut incoming = BoundedIncoming::new(
        tokio_stream::wrappers::ReceiverStream::new(receiver),
        Arc::clone(&semaphore),
    );
    std::future::poll_fn(|cx| {
        assert!(Pin::new(&mut incoming).poll_next(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(semaphore.available_permits(), 0);
    sender
        .send(Err::<tokio::io::DuplexStream, _>(io::Error::other(
            "injected accept error",
        )))
        .await
        .unwrap();
    assert_eq!(
        incoming.next().await.unwrap().err().unwrap().kind(),
        io::ErrorKind::Other
    );
    assert_eq!(semaphore.available_permits(), 1);
    let held = Arc::clone(&semaphore).acquire_owned().await.unwrap();
    std::future::poll_fn(|cx| {
        assert!(Pin::new(&mut incoming).poll_next(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(held);
    let (accepted, _peer) = tokio::io::duplex(64);
    sender.send(Ok(accepted)).await.unwrap();
    drop(incoming.next().await.unwrap().unwrap());
    assert_eq!(semaphore.available_permits(), 1);
    drop(sender);
    assert!(incoming.next().await.is_none());
    semaphore.close();
    assert!(incoming.next().await.is_none());
}
