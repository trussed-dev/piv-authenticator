use crate::{Authenticator, constants::PIV_AID, Result};

use apdu_dispatch::{
    app::{Aid, App},
    command::Size as CommandSize,
    Command,
    response::{Data, Size as ResponseSize},
};
use trussed::client;

impl<T> Aid for Authenticator<CommandSize, T> {

    fn aid(&self) -> &'static [u8] {
        &PIV_AID
    }

    fn right_truncated_length(&self) -> usize {
        11
    }
}


#[cfg(feature = "apdu-dispatch")]
impl<T> App<CommandSize, ResponseSize> for Authenticator<CommandSize, T>
where
    T: client::Client + client::Ed255 + client::Tdes
{
    fn select(&mut self, apdu: &Command, reply: &mut Data) -> Result {
        self.select(apdu, reply)
    }

    fn deselect(&mut self) { self.deselect() }

    fn call(&mut self, _: iso7816::Interface, apdu: &Command, reply: &mut Data) -> Result {
        self.respond(apdu, reply)
    }
}
