// Copyright (C) 2022  Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(feature = "virtual")]

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
