const COMMAND_SIZE: usize = 3072;

#[macro_export]
macro_rules! cmd {
    ($tt:tt) => {
        iso7816::Command::<3072>::try_from(&hex_literal::hex!($tt)).unwrap()
    };
}

use trussed::virt::{Client, Ram};

pub type Piv<'service> = piv_authenticator::Authenticator<Client<Ram>, COMMAND_SIZE>;

pub fn piv<R>(test: impl FnOnce(&mut Piv) -> R) -> R {
    trussed::virt::with_ram_client("test", |client| {
        let mut piv_app = piv_authenticator::Authenticator::new(client);
        test(&mut piv_app)
    })
}
