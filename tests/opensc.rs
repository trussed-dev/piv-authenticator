pub mod card;

use std::process::Command;

use card::*;

use expectrl::process::unix::WaitStatus;
use expectrl::{spawn, Eof, Expect};

const CARD: &str = env!("PIV_DANGEROUS_TEST_CARD_READER");

use std::time::Duration;
const EXPECT_TIMEOUT: Option<Duration> = Some(Duration::from_secs(30));

#[test_log::test]
fn list() {
    let test = || {
        let p = spawn("piv-tool -n").unwrap();
        let mut logger = LogWriter(Vec::new());
        let mut p = expectrl::session::log(p, &mut logger).unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(format!("Using reader with a card: {CARD}"))
            .unwrap();
        p.expect("Personal Identity Verification Card").unwrap();
        p.expect(Eof).unwrap();
        let WaitStatus::Exited(pid, exit_code) = p.get_process().wait().unwrap() else {
            panic!("Got wrong wait status");
        };
        assert_eq!(pid, p.get_process().pid());
        // Some old versions on opensc could return 1 even on success.
        assert!(
            [0, 1].contains(&exit_code),
            "Unexpectedexitcode: {exit_code}"
        );
    };
    if card::dangerous_real_card_enabled() {
        with_lock_and_reset(test)
    } else {
        with_vsc(WITHOUT_UUID, test);
        with_vsc(WITH_UUID, test);
    }
}

#[test_log::test]
fn admin_mutual() {
    let test = || {
        let mut command = Command::new("piv-tool");
        command
            .env("PIV_EXT_AUTH_KEY", "tests/default_admin_key")
            .args(["-A", "M:9B:03"]);
        let p = expectrl::session::Session::spawn(command).unwrap();
        let mut logger = LogWriter(Vec::new());
        let mut p = expectrl::session::log(p, &mut logger).unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(format!("Using reader with a card: {CARD}"))
            .unwrap();
        // p.expect("Personal Identity Verification Card").unwrap();
        p.expect(Eof).unwrap();
        let WaitStatus::Exited(pid, exit_code) = p.get_process().wait().unwrap() else {
            panic!("Got wrong wait status");
        };
        assert_eq!(pid, p.get_process().pid());
        // Some old versions on opensc could return 1 even on success.
        assert!(
            [0, 1].contains(&exit_code),
            "Unexpectedexitcode: {exit_code}"
        );
    };
    if card::dangerous_real_card_enabled() {
        with_lock_and_reset(test)
    } else {
        with_vsc(WITHOUT_UUID, test);
        with_vsc(WITH_UUID, test);
    }
}

#[test_log::test]
fn admin_card() {
    let test = || {
        let mut command = Command::new("piv-tool");
        command
            .env("PIV_EXT_AUTH_KEY", "tests/default_admin_key")
            .args(["-A", "A:9B:03"]);
        let p = expectrl::session::Session::spawn(command).unwrap();
        let mut logger = LogWriter(Vec::new());
        let mut p = expectrl::session::log(p, &mut logger).unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(format!("Using reader with a card: {CARD}"))
            .unwrap();
        p.expect(Eof).unwrap();
        let WaitStatus::Exited(pid, exit_code) = p.get_process().wait().unwrap() else {
            panic!("Got wrong wait status");
        };
        assert_eq!(pid, p.get_process().pid());
        // Some old versions on opensc could return 1 even on success.
        assert!(
            [0, 1].contains(&exit_code),
            "Unexpectedexitcode: {exit_code}"
        );
    };
    if card::dangerous_real_card_enabled() {
        with_lock_and_reset(test)
    } else {
        with_vsc(WITHOUT_UUID, test);
        with_vsc(WITH_UUID, test);
    }
}

#[test_log::test]
fn admin_mutual_bad_key() {
    let test = || {
        let mut command = Command::new("piv-tool");
        command
            .env("PIV_EXT_AUTH_KEY", "tests/bad_admin_key")
            .args(["-A", "M:9B:03"]);
        let p = expectrl::session::Session::spawn(command).unwrap();
        let mut logger = LogWriter(Vec::new());
        let mut p = expectrl::session::log(p, &mut logger).unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(format!("Using reader with a card: {CARD}"))
            .unwrap();
        p.expect(" admin_mode failed -1205").unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(
            p.get_process().wait().unwrap(),
            WaitStatus::Exited(p.get_process().pid(), 75)
        );
    };
    if card::dangerous_real_card_enabled() {
        with_lock_and_reset(test)
    } else {
        with_vsc(WITHOUT_UUID, test);
        with_vsc(WITH_UUID, test);
    }
}

#[test_log::test]
fn admin_card_bad_key() {
    let test = || {
        let mut command = Command::new("piv-tool");
        command
            .env("PIV_EXT_AUTH_KEY", "tests/bad_admin_key")
            .args(["-A", "A:9B:03"]);
        let p = expectrl::session::Session::spawn(command).unwrap();
        let mut logger = LogWriter(Vec::new());
        let mut p = expectrl::session::log(p, &mut logger).unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(format!("Using reader with a card: {CARD}"))
            .unwrap();
        p.expect(" admin_mode failed -1205").unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(
            p.get_process().wait().unwrap(),
            WaitStatus::Exited(p.get_process().pid(), 75)
        );
    };
    if card::dangerous_real_card_enabled() {
        with_lock_and_reset(test)
    } else {
        with_vsc(WITHOUT_UUID, test);
        with_vsc(WITH_UUID, test);
    }
}

#[test_log::test]
fn generate_key() {
    let test = || {
        let mut command = Command::new("piv-tool");
        command
            .env("PIV_EXT_AUTH_KEY", "tests/default_admin_key")
            .args(["-A", "M:9B:03", "-G", "9A:11"]);
        let p = expectrl::session::Session::spawn(command).unwrap();
        let mut logger = LogWriter(Vec::new());
        let mut p = expectrl::session::log(p, &mut logger).unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(format!("Using reader with a card: {CARD}"))
            .unwrap();
        p.expect(Eof).unwrap();
        let WaitStatus::Exited(pid, exit_code) = p.get_process().wait().unwrap() else {
            panic!("Got wrong wait status");
        };
        assert_eq!(pid, p.get_process().pid());
        // Some old versions on opensc could return 1 even on success.
        assert!(
            [0, 1].contains(&exit_code),
            "Unexpectedexitcode: {exit_code}"
        );
    };
    if card::dangerous_real_card_enabled() {
        with_lock_and_reset(test)
    } else {
        with_vsc(WITHOUT_UUID, test);
        with_vsc(WITH_UUID, test);
    }

    let test = || {
        let mut command = Command::new("piv-tool");
        command
            .env("PIV_EXT_AUTH_KEY", "tests/default_admin_key")
            .args(["-A", "M:9B:03", "-G", "9A:07"]);
        let p = expectrl::session::Session::spawn(command).unwrap();
        let mut logger = LogWriter(Vec::new());
        let mut p = expectrl::session::log(p, &mut logger).unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(format!("Using reader with a card: {CARD}"))
            .unwrap();
        p.expect(Eof).unwrap();
        let WaitStatus::Exited(pid, exit_code) = p.get_process().wait().unwrap() else {
            panic!("Got wrong wait status");
        };
        assert_eq!(pid, p.get_process().pid());
        // Some old versions on opensc could return 1 even on success.
        assert!(
            [0, 1].contains(&exit_code),
            "Unexpectedexitcode: {exit_code}"
        );
    };
    if card::dangerous_real_card_enabled() {
        with_lock_and_reset(test)
    } else {
        with_vsc(WITHOUT_UUID, test);
        with_vsc(WITH_UUID, test);
    }
}
