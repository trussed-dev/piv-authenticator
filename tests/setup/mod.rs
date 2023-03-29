// Copyright (C) 2022 Nicolas Stalder AND  Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#[allow(unused)]
pub const COMMAND_SIZE: usize = 3072;

#[macro_export]
macro_rules! cmd {
    ($tt:tt) => {
        iso7816::Command::<3072>::try_from(&hex_literal::hex!($tt)).unwrap()
    };
}

use piv_authenticator::{Authenticator, Options};
use trussed::virt::Ram;
use trussed_rsa_alloc::virt::Client;

pub type Piv = piv_authenticator::Authenticator<Client<Ram>>;

pub fn piv<R>(test: impl FnOnce(&mut Piv) -> R) -> R {
    trussed_rsa_alloc::virt::with_ram_client("test", |client| {
        let mut piv_app = Authenticator::new(client, Options::default());
        test(&mut piv_app)
    })
}
