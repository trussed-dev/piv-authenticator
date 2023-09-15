// To use this, make sure that you have vpcd from vsmartcard installed and configured (e. g.
// install vsmartcard-vpcd on Debian).  You might have to restart your pcscd, e. g.
// `systemctl restart pcscd pcscd.socket`.
//
// Now you should be able to see the card in `pcsc_scan` and talk to it with `piv-tool`r
//
// Set `RUST_LOG=piv_authenticator::card=info` to see the executed commands.

// TODO: add CLI

use piv_authenticator::{virt::with_ram_client, Authenticator, Options};

fn main() {
    env_logger::init();

    with_ram_client("piv-authenticator", |client| {
        let card = Authenticator::new(client, Options::default());
        let mut vpicc_card = piv_authenticator::vpicc::VpiccCard::new(card);
        let vpicc = vpicc::connect().expect("failed to connect to vpicc");
        vpicc
            .run(&mut vpicc_card)
            .expect("failed to run vpicc smartcard");
    });
}
