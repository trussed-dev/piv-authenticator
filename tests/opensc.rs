// Copyright (C) 2022  Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(all(feature = "vpicc", feature = "opensc-tests"))]

mod card;

use std::process::Command;

use card::with_vsc;

use expectrl::{spawn, Eof, WaitStatus};

#[test_log::test]
fn list() {
    with_vsc(|| {
        let mut p = spawn("piv-tool -n").unwrap();
        p.expect("Using reader with a card: Virtual PCD 00 00")
            .unwrap();
        p.expect("Personal Identity Verification Card").unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(p.wait().unwrap(), WaitStatus::Exited(p.pid(), 0));
    });
}

#[test_log::test]
fn admin_mutual() {
    with_vsc(|| {
        let mut command = Command::new("piv-tool");
        command
            .env("PIV_EXT_AUTH_KEY", "tests/default_admin_key")
            .args(["-A", "M:9B:03"]);
        let mut p = expectrl::session::Session::spawn(command).unwrap();
        p.expect("Using reader with a card: Virtual PCD 00 00")
            .unwrap();
        // p.expect("Personal Identity Verification Card").unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(p.wait().unwrap(), WaitStatus::Exited(p.pid(), 0));
    });
}

/// Fails because of https://github.com/OpenSC/OpenSC/issues/2658
#[test_log::test]
#[ignore]
fn admin_card() {
    with_vsc(|| {
        let mut command = Command::new("piv-tool");
        command
            .env("PIV_EXT_AUTH_KEY", "tests/default_admin_key")
            .args(["-A", "A:9B:03"]);
        let mut p = expectrl::session::Session::spawn(command).unwrap();
        p.expect("Using reader with a card: Virtual PCD 00 00")
            .unwrap();
        p.expect("Personal Identity Verification Card").unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(p.wait().unwrap(), WaitStatus::Exited(p.pid(), 0));
    });
}

#[test_log::test]
fn generate_key() {
    // with_vsc(|| {
    //     let mut command = Command::new("piv-tool");
    //     command
    //         .env("PIV_EXT_AUTH_KEY", "tests/default_admin_key")
    //         .args(["-A", "M:9B:03", "-G", "9A:11"]);
    //     let mut p = expectrl::session::Session::spawn(command).unwrap();
    //     p.expect("Using reader with a card: Virtual PCD 00 00")
    //         .unwrap();
    //     p.expect(Eof).unwrap();
    //     // Non zero exit code?
    //     assert_eq!(p.wait().unwrap(), WaitStatus::Exited(p.pid(), 1));
    // });
    // with_vsc(|| {
    //     let mut command = Command::new("piv-tool");
    //     command
    //         .env("PIV_EXT_AUTH_KEY", "tests/default_admin_key")
    //         .args(["-A", "M:9B:03", "-G", "9A:07"]);
    //     let mut p = expectrl::session::Session::spawn(command).unwrap();
    //     p.expect("Using reader with a card: Virtual PCD 00 00")
    //         .unwrap();
    //     p.expect(Eof).unwrap();
    //     // Non zero exit code?
    //     assert_eq!(p.wait().unwrap(), WaitStatus::Exited(p.pid(), 1));
    // });
}
