// Copyright (C) 2022  Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(all(feature = "virtual", feature = "pivy-tests"))]

mod card;

use card::with_vsc;

use expectrl::{spawn, Eof, Regex, WaitStatus};

use std::io::Write;
use std::process::{Command, Stdio};

#[test_log::test]
fn list() {
    with_vsc(|| {
        let mut p = spawn("pivy-tool list").unwrap();
        p.expect(Regex("card: [0-9A-Z]*")).unwrap();
        p.expect("device: Virtual PCD 00 00").unwrap();
        p.expect("chuid: ok").unwrap();
        p.expect(Regex("guid: [0-9A-Z]*")).unwrap();
        p.expect("algos: 3DES AES256 ECCP256 (null) (null)")
            .unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(p.wait().unwrap(), WaitStatus::Exited(p.pid(), 0));
    });
}

#[test_log::test]
fn generate() {
    with_vsc(|| {
        let mut p = spawn("pivy-tool -A 3des -K 010203040506070801020304050607080102030405060708 generate 9A -a eccp256 -P 123456").unwrap();
        p.expect(Regex(
            "ecdsa-sha2-nistp256 (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)? PIV_slot_9A@[A-F0-9]{20}",
        ))
        .unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(p.wait().unwrap(), WaitStatus::Exited(p.pid(), 0));
    });
}

#[test_log::test]
fn ecdh() {
    with_vsc(|| {
        let mut p = spawn("pivy-tool -A 3des -K 010203040506070801020304050607080102030405060708 generate 9A -a eccp256 -P 123456").unwrap();
        p.expect(Regex(
            "ecdsa-sha2-nistp256 (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)? PIV_slot_9A@[A-F0-9]{20}",
        ))
        .unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(p.wait().unwrap(), WaitStatus::Exited(p.pid(), 0));

        let mut p = Command::new("pivy-tool")
            .args(["ecdh", "9A", "-P", "123456"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = p.stdin.take().unwrap();
        write!(stdin,
            "ecdsa-sha2-nistp256 \
                AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIK+WUxBiBEwHgT4ykw3FDC1kRRMZCQo2+iM9+8WQgz7eFhEcU78eVweIrqG0nyJaZeWhgcYTSDP+VisDftiQgo= \
                PIV_slot_9A@6E9BCA45D8AF4B9D95AA2E8C8C23BA49"        ).unwrap();
        drop(stdin);

        assert_eq!(p.wait().unwrap().code(), Some(0));
    });
}
