use piv_authenticator::{virt::with_ram_client, vpicc::VpiccCard, Authenticator, Options};

use std::{sync::mpsc, thread::sleep, time::Duration};
use stoppable_thread::spawn;

use std::panic::{catch_unwind, resume_unwind, UnwindSafe};
use std::process::Command;
use std::sync::Mutex;

static VSC_MUTEX: Mutex<()> = Mutex::new(());

#[cfg_attr(feature = "dangerous-test-real-card", expect(unused))]
pub const WITH_UUID: Options = Options::new().uuid(Some([0; 16]));
#[cfg_attr(feature = "dangerous-test-real-card", expect(unused))]
pub const WITHOUT_UUID: Options = Options::new();

#[cfg_attr(feature = "dangerous-test-real-card", expect(unused))]
pub fn with_vsc<F: FnOnce() -> R, R>(options: Options, f: F) -> R {
    let Ok(_lock) = VSC_MUTEX.lock() else {
        panic!("Some other test failed, this test is therefore ignored")
    };

    let mut vpicc = vpicc::connect().expect("failed to connect to vpcd");

    let (tx, rx) = mpsc::channel();
    let handle = spawn(move |stopped| {
        with_ram_client("opcard", |client| {
            let card = Authenticator::new(client, options);
            let mut vpicc_card = VpiccCard::new(card);
            let mut result = Ok(());
            while !stopped.get() && result.is_ok() {
                result = vpicc.poll(&mut vpicc_card);
                if result.is_ok() {
                    tx.send(()).expect("failed to send message");
                }
            }
            result
        })
    });

    rx.recv().expect("failed to read message");

    sleep(Duration::from_millis(200));

    let result = f();

    handle
        .stop()
        .join()
        .expect("failed to join vpicc thread")
        .expect("failed to run vpicc smartcard");
    result
}

#[cfg_attr(not(feature = "dangerous-test-real-card"), expect(unused))]
pub fn with_lock_and_reset<F: UnwindSafe + FnOnce() -> R, R: UnwindSafe>(f: F) {
    let lock = VSC_MUTEX.lock();
    let res = catch_unwind(f);
    let output = Command::new("piv-tool")
        .args([
            "-s",
            "00:20:00:80:08:0102030405060708",
            "-s",
            "00:20:00:80:08:0102030405060708",
            "-s",
            "00:20:00:80:08:0102030405060708", //Locked pin
            "-s",
            "00:FB:00:00",
        ])
        .output()
        .unwrap();
    if let Err(err) = res {
        resume_unwind(err)
    }

    println!("Out: {}", String::from_utf8_lossy(&output.stdout));
    println!("Err: {}", String::from_utf8_lossy(&output.stderr));

    assert!(output.status.success());

    drop(lock);
}
