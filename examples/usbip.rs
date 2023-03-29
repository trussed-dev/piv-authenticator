// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

use trussed::virt::{self, Ram, UserInterface};
use trussed::{ClientImplementation, Platform};

use piv_authenticator as piv;
use trussed_usbip::Syscall;

const MANUFACTURER: &str = "Nitrokey";
const PRODUCT: &str = "Nitrokey 3";
const VID: u16 = 0x20a0;
const PID: u16 = 0x42b2;

struct PivApp {
    piv: piv::Authenticator<ClientImplementation<Syscall<virt::Platform<Ram>>>>,
}

impl trussed_usbip::Apps<ClientImplementation<Syscall<virt::Platform<Ram>>>, ()> for PivApp {
    fn new(
        make_client: impl Fn(&str) -> ClientImplementation<Syscall<virt::Platform<Ram>>>,
        _data: (),
    ) -> Self {
        PivApp {
            piv: piv::Authenticator::new(make_client("piv"), piv::Options::default()),
        }
    }

    fn with_ccid_apps<T>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn apdu_dispatch::App<7609, 7609>]) -> T,
    ) -> T {
        f(&mut [&mut self.piv])
    }
}

fn main() {
    env_logger::init();

    let options = trussed_usbip::Options {
        manufacturer: Some(MANUFACTURER.to_owned()),
        product: Some(PRODUCT.to_owned()),
        serial_number: Some("TEST".into()),
        vid: VID,
        pid: PID,
    };
    trussed_usbip::Runner::new(virt::Ram::default(), options)
        .init_platform(move |platform| {
            let ui: Box<dyn trussed::platform::UserInterface + Send + Sync> =
                Box::new(UserInterface::new());
            platform.user_interface().set_inner(ui);
        })
        .exec::<PivApp, _, _>(|_platform| {});
}
