// Copyright (C) 2022  Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(all(feature = "virtual", feature = "opensc-tests"))]

mod card;

use card::with_vsc;

use expectrl::{spawn, Eof, Regex, WaitStatus};

#[test]
fn list() {
    with_vsc(|| {
        let mut p = spawn("piv-tool -n").unwrap();
        p.check("Using reader with a card: Virtual PCD 00 00")
            .unwrap();
        p.check("Personal Identity Verification Card").unwrap();
        p.check(Eof).unwrap();
        assert_eq!(p.wait().unwrap(), WaitStatus::Exited(p.pid(), 0));
    });
}
