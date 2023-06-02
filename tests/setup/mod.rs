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

use piv_authenticator::{
    virt::{with_ram_client, VirtClient},
    Authenticator, Options,
};
use trussed::virt::Ram;

pub type Piv = piv_authenticator::Authenticator<VirtClient<Ram>>;

pub const WITHOUT_UUID: Options = Options::new();

pub fn piv<R>(options: Options, test: impl FnOnce(&mut Piv) -> R) -> R {
    with_ram_client("test", |client| {
        let mut piv_app = Authenticator::new(client, options);
        test(&mut piv_app)
    })
}
