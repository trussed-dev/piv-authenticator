// Copyright (C) 2022  Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(all(feature = "virtual", feature = "pivy-tests"))]

mod card;

use card::with_vsc;

use expectrl::{spawn, Eof, Regex, WaitStatus};

#[test]
fn list() {
    with_vsc(|| {
        let mut p = spawn("pivy-tool list").unwrap();
        p.check(Regex("card: [0-9A-Z]*")).unwrap();
        p.check("device: Virtual PCD 00 00").unwrap();
        p.check("chuid: ok").unwrap();
        p.check(Regex("guid: [0-9A-Z]*")).unwrap();
        p.check("algos: 3DES AES256 ECCP256 (null) (null)").unwrap();
        p.check(Eof).unwrap();
        assert_eq!(p.wait().unwrap(), WaitStatus::Exited(p.pid(), 0));
    });
}

#[test]
fn generate() {
    with_vsc(|| {
        let mut p = spawn("pivy-tool -A 3des -K 010203040506070801020304050607080102030405060708 generate 9A -a eccp256 -P 123456").unwrap();
        p.check("Touch button confirmation may be required.")
            .unwrap();
        p.check(Regex(
            "^ecdsa-sha2-nistp256 (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)? PIV_slot_9A@[A-F0-9]{20}$",
        ))
        .unwrap();
        p.check(Eof).unwrap();
        assert_eq!(p.wait().unwrap(), WaitStatus::Exited(p.pid(), 0));
    });
}
