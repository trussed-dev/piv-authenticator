#![cfg(all(feature = "vpicc", feature = "opensc-tests"))]

mod card;

use std::process::Command;

use card::*;

use cfg_if::cfg_if;
use expectrl::{spawn, Eof, WaitStatus};

const CARD: &str = env!("PIV_DANGEROUS_TEST_CARD_READER");

use std::time::Duration;
const EXPECT_TIMEOUT: Option<Duration> = Some(Duration::from_secs(30));

#[test_log::test]
fn list() {
    let test = || {
        let mut p = spawn("piv-tool -n").unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(format!("Using reader with a card: {CARD}"))
            .unwrap();
        p.expect("Personal Identity Verification Card").unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(
            p.get_process().wait().unwrap(),
            WaitStatus::Exited(p.get_process().pid(), 0)
        );
    };
    cfg_if! {
        if #[cfg(not(feature = "dangerous-test-real-card"))] {
            with_vsc(WITHOUT_UUID, test);
            with_vsc(WITH_UUID, test);
        } else {
            with_lock_and_reset(test)
        }
    }
}

#[test_log::test]
fn admin_mutual() {
    let test = || {
        let mut command = Command::new("piv-tool");
        command
            .env("PIV_EXT_AUTH_KEY", "tests/default_admin_key")
            .args(["-A", "M:9B:03"]);
        let mut p = expectrl::session::Session::spawn(command).unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(format!("Using reader with a card: {CARD}"))
            .unwrap();
        // p.expect("Personal Identity Verification Card").unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(
            p.get_process().wait().unwrap(),
            WaitStatus::Exited(p.get_process().pid(), 0)
        );
    };
    cfg_if! {
        if #[cfg(not(feature = "dangerous-test-real-card"))]{
            with_vsc(WITH_UUID, test);
            with_vsc(WITHOUT_UUID, test);
        } else {
            with_lock_and_reset(test)
        }
    }
}

#[test_log::test]
fn admin_card() {
    let test = || {
        let mut command = Command::new("piv-tool");
        command
            .env("PIV_EXT_AUTH_KEY", "tests/default_admin_key")
            .args(["-A", "A:9B:03"]);
        let mut p = expectrl::session::Session::spawn(command).unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect("Using reader with a card: Virtual PCD 00 00")
            .unwrap();
        // p.expect("Personal Identity Verification Card").unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(
            p.get_process().wait().unwrap(),
            WaitStatus::Exited(p.get_process().pid(), 0)
        );
    };
    cfg_if! {
        if #[cfg(not(feature = "dangerous-test-real-card"))]{
            with_vsc(WITH_UUID, test);
            with_vsc(WITHOUT_UUID, test);
        } else {
            with_lock_and_reset(test)
        }
    }
}

#[test_log::test]
fn generate_key() {
    let test = || {
        let mut command = Command::new("piv-tool");
        command
            .env("PIV_EXT_AUTH_KEY", "tests/default_admin_key")
            .args(["-A", "M:9B:03", "-G", "9A:11"]);
        let mut p = expectrl::session::Session::spawn(command).unwrap();
        p.expect("Using reader with a card: Virtual PCD 00 00")
            .unwrap();
        p.expect(Eof).unwrap();
        // Non zero exit code?
        assert_eq!(
            p.get_process().wait().unwrap(),
            WaitStatus::Exited(p.get_process().pid(), 1)
        );
    };
    cfg_if! {
        if #[cfg(not(feature = "dangerous-test-real-card"))]{
            with_vsc(WITH_UUID, test);
            with_vsc(WITHOUT_UUID, test);
        } else {
            with_lock_and_reset(test)
        }
    }

    let test = || {
        let mut command = Command::new("piv-tool");
        command
            .env("PIV_EXT_AUTH_KEY", "tests/default_admin_key")
            .args(["-A", "M:9B:03", "-G", "9A:07"]);
        let mut p = expectrl::session::Session::spawn(command).unwrap();
        p.expect("Using reader with a card: Virtual PCD 00 00")
            .unwrap();
        p.expect(Eof).unwrap();
        // Non zero exit code?
        assert_eq!(
            p.get_process().wait().unwrap(),
            WaitStatus::Exited(p.get_process().pid(), 1)
        );
    };
    cfg_if! {
        if #[cfg(not(feature = "dangerous-test-real-card"))]{
            with_vsc(WITH_UUID, test);
            with_vsc(WITHOUT_UUID, test);
        } else {
            with_lock_and_reset(test)
        }
    }
}
