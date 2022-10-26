// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

// To use this, make sure that you have vpcd from vsmartcard installed and configured (e. g.
// install vsmartcard-vpcd on Debian).  You might have to restart your pcscd, e. g.
// `systemctl restart pcscd pcscd.socket`.
//
// Now you should be able to see the card in `pcsc_scan` and talk to it with `piv-tool`r
//
// Set `RUST_LOG=piv_authenticator::card=info` to see the executed commands.

// TODO: add CLI

fn main() {
    env_logger::init();

    trussed::virt::with_ram_client("opcard", |client| {
        let card = piv_authenticator::Authenticator::new(client);
        let mut virtual_card = piv_authenticator::vpicc::VirtualCard::new(card);
        let vpicc = vpicc::connect().expect("failed to connect to vpicc");
        vpicc
            .run(&mut virtual_card)
            .expect("failed to run virtual smartcard");
    });
}