//! Standalone compiler negative control. Never linked into a product target.
//! A region-derived success count must not invent a successful Result edge
//! when the only outcomes were Err and a caught callee unwind.

use std::sync::atomic::{AtomicUsize, Ordering};

static QUESTION_SUCCESSES: AtomicUsize = AtomicUsize::new(0);
static EXPLICIT_SUCCESSES: AtomicUsize = AtomicUsize::new(0);

#[inline(never)]
fn callee(unwind: bool) -> Result<(), u8> {
    if unwind {
        panic!("intentional compiler measurement control");
    }
    Err(7)
}

#[inline(never)]
fn question(unwind: bool) -> Result<(), u8> {
    callee(unwind)?;
    QUESTION_SUCCESSES.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

#[inline(never)]
fn explicit(unwind: bool) -> Result<(), u8> {
    let result = callee(unwind);
    if let Err(error) = result {
        return Err(error);
    }
    EXPLICIT_SUCCESSES.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    assert_eq!(question(false), Err(7));
    assert!(std::panic::catch_unwind(|| question(true)).is_err());
    assert_eq!(explicit(false), Err(7));
    assert!(std::panic::catch_unwind(|| explicit(true)).is_err());
    assert_eq!(QUESTION_SUCCESSES.load(Ordering::SeqCst), 0);
    assert_eq!(EXPLICIT_SUCCESSES.load(Ordering::SeqCst), 0);
    println!("question_successes=0 explicit_successes=0");
}
